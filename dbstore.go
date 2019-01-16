package bestore

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	"github.com/sethvargo/go-password/password"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/bcrypt"
)

type DBStore struct {
	gdb *gorm.DB
}

func NewDBStore(connStr string, runMode string) (*DBStore, error) {
	gdb, err := gorm.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	switch runMode {
	case "production", "testing":
		gdb.LogMode(false)
	case "development":
		gdb.LogMode(true)
	default:
		return nil, errors.New("invalid mode")
	}

	return &DBStore{gdb: gdb}, nil
}

func (s *DBStore) AddUser(externalID, email, password, name, avatarURL string) (
	User, error) {

	if externalID == "" && email == "" {
		return User{}, errors.New(
			"both external ID and email are empty")
	}

	tx := s.gdb.Begin()
	if tx.Error != nil {
		return User{}, tx.Error
	}

	var count uint

	err := tx.Model(&User{}).Where(&User{ExternalID: externalID,
		Email: email}).Count(&count).Error
	if err != nil {
		tx.Rollback()
		return User{}, err
	}

	if count != 0 {
		tx.Rollback()
		return User{}, ErrDuplicateUser
	}

	var passwordHash []byte

	if password != "" {
		passwordHash, err = bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.DefaultCost)
		if err != nil {
			tx.Rollback()
			return User{}, errors.New("failed to hash password: " + err.Error())
		}
	}

	u := User{
		ExternalID:   externalID,
		Email:        email,
		PasswordHash: passwordHash,
		Name:         name,
		AvatarURL:    avatarURL,
	}

	err = tx.Create(&u).Error
	if err != nil {
		tx.Rollback()
		return u, err
	}

	return u, tx.Commit().Error
}

func (s *DBStore) GetUserByID(userID uint) (u User,
	err error) {
	err = s.gdb.Where(&User{ID: userID}).
		Take(&u).Error
	return
}

func (s *DBStore) GetUserByExternalID(externalID string) (u User,
	err error) {
	err = s.gdb.Where(&User{ExternalID: externalID}).
		Take(&u).Error
	return
}

func (s *DBStore) GetUserByEmail(email string) (u User,
	err error) {
	err = s.gdb.Where(&User{Email: email}).
		Take(&u).Error
	return
}

func (s *DBStore) AuthorizeUser(email, password string) (u User,
	err error) {
	err = s.gdb.Where(&User{Email: email}).Take(&u).Error
	if err != nil {
		return
	}
	err = bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password))
	return
}

func (s *DBStore) SetUserEmail(userID uint, email string) error {
	return s.gdb.Model(&User{}).
		Where(&User{ID: userID}).
		Update(map[string]interface{}{"email": email,
			"email_confirmed": false}).
		Error
}

func (s *DBStore) SetUserEmailConfirmed(userID uint, confirmed bool) error {
	return s.gdb.Model(&User{}).
		Where(&User{ID: userID}).
		Update(&User{EmailConfirmed: confirmed}).
		Error
}

func (s *DBStore) SetUserPassword(userID uint, password string) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.gdb.Model(&User{}).
		Where(&User{ID: userID}).
		Update(&User{PasswordHash: passwordHash}).
		Error
}

func (s *DBStore) SetUserName(userID uint, name string) error {
	return s.gdb.Model(&User{}).
		Where(&User{ID: userID}).
		Update(&User{Name: name}).
		Error
}

func (s *DBStore) SetUserAvatarURL(userID uint, avatarURL string) error {
	return s.gdb.Model(&User{}).
		Where(&User{ID: userID}).
		Update(&User{AvatarURL: avatarURL}).
		Error
}

func (s DBStore) GetUsers() (us []User, err error) {
	err = s.gdb.Order("id ASC").Find(&us).Error
	return
}

func (s *DBStore) AddUserPasswordReset(userID uint) (UserPasswordReset, error) {

	var pr UserPasswordReset

	tx := s.gdb.Begin()
	if tx.Error != nil {
		return pr, tx.Error
	}

	err := tx.Take(&pr, UserPasswordReset{UserID: userID}).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		tx.Rollback()
		return pr, err
	}

	notFound := err == gorm.ErrRecordNotFound

	code, err := password.Generate(64, 32, 0,
		true, true)
	if err != nil {
		tx.Rollback()
		return UserPasswordReset{}, err
	}

	pr.UserID = userID
	pr.Code = code
	pr.CreatedAt = time.Now()

	if notFound {
		err = tx.Create(&pr).Error
	} else {
		err = tx.Model(&UserPasswordReset{}).
			Where(&UserPasswordReset{UserID: userID}).
			Update(&pr).
			Error
	}
	if err != nil {
		tx.Rollback()
		return pr, err
	}

	return pr, tx.Commit().Error
}

func (s *DBStore) GetUserPasswordReset(code string) (pr UserPasswordReset,
	err error) {
	err = s.gdb.Where(&UserPasswordReset{Code: code}).Take(&pr).Error
	return
}

func (s *DBStore) RemoveUserPasswordReset(code string) error {
	return s.gdb.Where(&UserPasswordReset{Code: code}).
		Delete(&UserPasswordReset{}).
		Error
}

func (s *DBStore) AddUserEmailConfirmation(userID uint,
	email string) (UserEmailConfirmation, error) {

	var ec UserEmailConfirmation

	tx := s.gdb.Begin()
	if tx.Error != nil {
		return ec, tx.Error
	}

	err := tx.Take(&ec, UserEmailConfirmation{UserID: userID}).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		tx.Rollback()
		return ec, err
	}

	notFound := err == gorm.ErrRecordNotFound

	ec.Code, err = password.Generate(64, 32, 0,
		true, true)
	if err != nil {
		return ec, err
	}

	ec.UserID = userID
	ec.Email = email

	if notFound {
		err = s.gdb.Create(&ec).Error
	} else {
		err = s.gdb.Model(&UserEmailConfirmation{}).
			Where(&UserEmailConfirmation{UserID: userID}).
			Update(&ec).Error
	}

	if err != nil {
		tx.Rollback()
		return ec, err
	}

	return ec, tx.Commit().Error
}

func (s *DBStore) GetUserEmailConfirmation(userID uint) (ec UserEmailConfirmation,
	err error) {
	err = s.gdb.Where(&UserEmailConfirmation{UserID: userID}).
		Take(&ec).Error
	return
}

func (s *DBStore) RemoveUserEmailConfirmation(userID uint) error {
	return s.gdb.Where(&UserEmailConfirmation{UserID: userID}).
		Delete(&UserEmailConfirmation{}).
		Error
}

func (s *DBStore) GetProject(projectID uint) (p Project, err error) {
	err = s.gdb.Where(&Project{ID: projectID}).Take(&p).Error
	ps := []Project{p}
	err = s.setProjectsMiningStats(ps)
	p = ps[0]
	return
}

func (s *DBStore) AddProject(p Project) (Project, error) {
	np := Project{
		UserID:           p.UserID,
		Status:           DraftPS,
		Goal:             p.Goal,
		DurationDays:     p.DurationDays,
		CategoryID:       p.CategoryID,
		CityID:           p.CityID,
		Title:            p.Title,
		ShortDescription: p.ShortDescription,
		FullDescription:  p.FullDescription,
		CoverURL:         p.CoverURL,
		VideoURL:         p.VideoURL,
		FacebookURL:      p.FacebookURL,
		TwitterURL:       p.TwitterURL,
		Raised:           decimal.Zero,
		RaisedDate:       time.Now(),
		EarnBestMiner:    decimal.Zero,
	}
	err := s.gdb.Create(&np).Error
	return np, err
}

func (s *DBStore) checkProjectOwner(projectID uint, userID uint) error {
	var exists bool
	err := s.gdb.Raw(`
		SELECT EXISTS(
			SELECT 1
			FROM projects
			WHERE id = $1 AND user_id = $2
		)
	`, projectID, userID).Scan(&exists).Error
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidProjectOwner
	}
	return nil
}

var ErrNotInDraftStatus = errors.New("project is not in draft status")

func (s *DBStore) SetProject(p Project) error {
	err := s.checkProjectOwner(p.ID, p.UserID)
	if err != nil {
		return err
	}

	tx := s.gdb.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	var c int

	err = tx.Model(&Project{ID: p.ID}).
		Where(&Project{ID: p.ID, Status: DraftPS}).
		Count(&c).Error
	if err != nil {
		tx.Rollback()
		return tx.Error
	}

	if c != 1 {
		return errors.New("project is not in draft status")
	}

	np := Project{
		ID:               p.ID,
		Goal:             p.Goal,
		DurationDays:     p.DurationDays,
		CategoryID:       p.CategoryID,
		CityID:           p.CityID,
		Title:            p.Title,
		ShortDescription: p.ShortDescription,
		FullDescription:  p.FullDescription,
		CoverURL:         p.CoverURL,
		VideoURL:         p.VideoURL,
		FacebookURL:      p.FacebookURL,
		TwitterURL:       p.TwitterURL,
	}

	err = tx.Save(&np).Error
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (s *DBStore) GetProjects(limit uint, offset uint, userID uint,
	categoryID uint, statuses []ProjectStatus) (ps []Project, total uint,
	err error) {

	q := s.gdb.Model(&Project{}).
		Where(&Project{UserID: userID}).
		Where(&Project{CategoryID: categoryID}).
		Where("status IN (?)", statuses)

	err = q.Count(&total).Error
	if err != nil {
		return
	}

	err = q.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&ps).
		Error
	if err != nil {
		return
	}

	err = s.setProjectsMiningStats(ps)

	return
}

func (s *DBStore) setProjectsMiningStats(ps []Project) error {
	idToIdx := map[uint]int{}
	var ids []string

	for i, p := range ps {
		idToIdx[p.ID] = i
		ids = append(ids, strconv.FormatUint(uint64(p.ID), 10))
	}

	rows, err := s.gdb.DB().Query(`
		SELECT projectid, SUM(amount), MAX(updated), MAX(amount)
		FROM balances
		WHERE projectid IN (` + strings.Join(ids, ",") + `)
		GROUP BY projectid
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			projectID     uint
			raised        string
			raisedDate    time.Time
			earnBestMiner string
			err           error
		)

		err = rows.Scan(&projectID, &raised, &raisedDate, &earnBestMiner)
		if err != nil {
			return err
		}

		i := idToIdx[projectID]

		ps[i].Raised, err = decimal.NewFromString(raised)
		if err != nil {
			return err
		}

		ps[i].RaisedDate = raisedDate

		ps[i].EarnBestMiner, err = decimal.NewFromString(earnBestMiner)
		if err != nil {
			return err
		}

	}
	if err := rows.Err(); err != nil {
		return err
	}

	return nil
}

func (s *DBStore) CheckCategoryID(categoryID uint) error {
	var exists bool
	err := s.gdb.Raw(`
		SELECT EXISTS(
			SELECT 1
			FROM project_categories
			WHERE id = $1
		)
	`, categoryID).Scan(&exists).Error
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidCategoryID
	}
	return nil
}

func (s *DBStore) AddCountry(id uint, name string) error {
	return s.gdb.Create(&Country{
		ID:   id,
		Name: name,
	}).Error
}

func (s *DBStore) GetCountries() (cs []Country, err error) {
	err = s.gdb.Model(&Country{}).Find(&cs).Error
	return
}

func (s *DBStore) AddCity(id uint, countryID uint, name string) error {
	return s.gdb.Create(&City{
		ID:        id,
		CountryID: countryID,
		Name:      name,
	}).Error
}

func (s *DBStore) GetCities(countryID uint) (cs []City, err error) {
	err = s.gdb.Model(&City{}).
		Where(&City{CountryID: countryID}).
		Find(&cs).
		Error
	return
}

func (s *DBStore) CheckCityID(cityID uint) error {
	var exists bool
	err := s.gdb.Raw(`
		SELECT EXISTS(
			SELECT 1
			FROM cities
			WHERE id = $1
		)
	`, cityID).Scan(&exists).Error
	if err != nil {
		return err
	}
	if !exists {
		return ErrInvalidCityID
	}
	return nil
}

func (s *DBStore) GetProjectCategories() (pcs []ProjectCategory, err error) {
	err = s.gdb.Model(&ProjectCategory{}).
		Order("name ASC").
		Find(&pcs).
		Error
	return
}
