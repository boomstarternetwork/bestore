package bestore

import (
	"errors"
	"fmt"
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

func (s *DBStore) AddUser(externalID, email, password, name, avatarURL, ethAddress string) (
	User, error) {

	if externalID == "" && email == "" {
		return User{}, errors.New(
			"both external ID and email are empty")
	}

	email = strings.ToLower(email)

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
		EthAddress:   ethAddress,
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
	err = s.gdb.Where(&User{Email: strings.ToLower(email)}).
		Take(&u).Error
	return
}

func (s *DBStore) AuthorizeUser(email, password string) (u User,
	err error) {
	err = s.gdb.Where(&User{Email: strings.ToLower(email)}).Take(&u).Error
	if err != nil {
		return
	}

	err = bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password))
	return
}

func (s *DBStore) SetUserEmail(userID uint, email string) error {
	return s.gdb.Model(&User{}).
		Where(&User{ID: userID}).
		Update(map[string]interface{}{"email": strings.ToLower(email),
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

//
// Countries
//

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

//
// Cities
//

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
	var city City
	err := s.gdb.Take(&city, City{ID: cityID}).Error
	if gorm.IsRecordNotFoundError(err) {
		return ErrInvalidCityID
	}

	return err
}

//
// UserPassword
//

func (s *DBStore) GetUserPasswordReset(code string) (pr UserPasswordReset,
	err error) {
	err = s.gdb.Where(&UserPasswordReset{Code: code}).Take(&pr).Error
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

func (s *DBStore) RemoveUserPasswordReset(code string) error {
	return s.gdb.Where(&UserPasswordReset{Code: code}).
		Delete(&UserPasswordReset{}).
		Error
}

//
// UserEmailConfirmation
//

func (s *DBStore) GetUserEmailConfirmation(userID uint) (ec UserEmailConfirmation,
	err error) {
	err = s.gdb.Take(&ec, &UserEmailConfirmation{UserID: userID}).Error
	return
}

func (s *DBStore) GetUserEmailConfirmationByCode(code string) (ec UserEmailConfirmation,
	err error) {
	err = s.gdb.Take(&ec, &UserEmailConfirmation{Code: code}).Error
	return
}

func (s *DBStore) AddUserEmailConfirmation(userID uint,
	email string) (ec UserEmailConfirmation, err error) {

	code, err := password.Generate(64, 32, 0, true, true)
	if err != nil {
		return ec, err
	}

	email = strings.ToLower(email)

	err = s.gdb.Where(UserEmailConfirmation{UserID: userID}).
		Assign(UserEmailConfirmation{Email: email, Code: code}).
		FirstOrCreate(&ec).Error

	return
}
func (s *DBStore) RemoveUserEmailConfirmation(userID uint) error {
	return s.gdb.Where(UserEmailConfirmation{UserID: userID}).
		Delete(UserEmailConfirmation{}).
		Error
}

//
// KYC
//

func (s *DBStore) SetUserKYC(kyc UserKYC) error {
	return s.gdb.Where(UserKYC{UserID: kyc.UserID}).Assign(kyc).FirstOrCreate(&kyc).Error
}

func (s *DBStore) GetUserKYC(userID uint) (kyc UserKYC, err error) {
	err = s.gdb.Take(&kyc, UserKYC{UserID: userID}).Error
	return
}

//
// Withdraw
//

var ErrInvalidOperationStatus = errors.New("operation is not in success or failure status")

func (s *DBStore) SetUserWithdraw(userID uint, status OperationStatus, amount decimal.Decimal) error {
	var uw UserWithdraw
	// err := s.gdb.Take(&uw, UserWithdraw{UserID: userID}).Error
	// if err != nil && !gorm.IsRecordNotFoundError(err) {
	// 	return err
	// }

	// if uw.Status == InitOS || uw.Status == WIPOS {
	// 	return ErrInvalidOperationStatus
	// }

	uw.UserID = userID
	uw.Status = status
	uw.Amount = amount
	return s.gdb.Where(UserWithdraw{UserID: userID}).Assign(uw).FirstOrCreate(&uw).Error
}

func (s *DBStore) GetUserWithdraw(userID uint) (uw UserWithdraw, err error) {
	err = s.gdb.Take(&uw, UserWithdraw{UserID: userID}).Error
	return
}

func (s *DBStore) RemoveUserWithdraw(userID uint) error {
	var uw UserWithdraw
	err := s.gdb.Take(&uw, UserWithdraw{UserID: userID}).Error
	if err != nil {
		return err
	}

	if uw.Status == InitOS || uw.Status == WIPOS {
		return ErrInvalidOperationStatus
	}

	return s.gdb.Model(UserWithdraw{UserID: userID}).Delete(UserWithdraw{}).Error
}

//
// ProjectCategories
//

func (s *DBStore) AddProjectCategory(name string) (cat ProjectCategory, err error) {
	cat.Name = name
	err = s.gdb.Create(&cat).Error
	return
}

func (s *DBStore) GetProjectCategories() (pcs []ProjectCategory, err error) {
	err = s.gdb.Order("name ASC").Find(&pcs).Error
	return
}

func (s *DBStore) CheckProjectCategoryID(categoryID uint) error {
	var cat ProjectCategory
	err := s.gdb.Take(&cat, ProjectCategory{ID: categoryID}).Error
	if gorm.IsRecordNotFoundError(err) {
		return ErrInvalidCategoryID
	}
	return err
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

func (s *DBStore) GetProject(projectID uint) (p Project, err error) {
	err = s.gdb.Where(&Project{ID: projectID}).Take(&p).Error
	ps := []Project{p}
	err = s.setProjectsMiningStats(ps)
	p = ps[0]
	return
}

func (s *DBStore) checkProjectOwner(projectID uint, userID uint) error {
	var p Project
	return s.gdb.Take(&p, Project{ID: projectID, UserID: userID}).Error
}

var ErrNotInDraftStatus = errors.New("project is not in draft status")

func (s *DBStore) SetProject(p Project) (Project, error) {
	err := s.checkProjectOwner(p.ID, p.UserID)
	if err != nil {
		return Project{}, err
	}

	tx := s.gdb.Begin()
	if tx.Error != nil {
		return Project{}, tx.Error
	}

	var c int

	err = tx.Model(&Project{ID: p.ID}).
		Where(&Project{ID: p.ID, Status: DraftPS}).
		Count(&c).Error
	if err != nil {
		tx.Rollback()
		return Project{}, tx.Error
	}

	if c != 1 {
		return Project{}, ErrNotInDraftStatus
	}

	np := Project{
		ID:               p.ID,
		UserID:           p.UserID,
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

	err = tx.Model(Project{ID: p.ID}).Updates(&np).Error
	if err != nil {
		tx.Rollback()
		return np, err
	}

	return np, tx.Commit().Error
}

func (s *DBStore) SetProjectModerationStatus(projectID uint, moderationStatus OperationStatus) error {
	return s.gdb.Model(Project{ID: projectID}).Updates(Project{ModerationStatus: moderationStatus}).Error
}

func (s *DBStore) GetProjects(limit uint, offset uint, userID uint,
	categoryID uint, statuses []ProjectStatus) (ps []Project, total uint,
	err error) {

	q := s.gdb.Model(&Project{})

	//filter by specified
	if userID > 0 {
		q = q.Where(&Project{UserID: userID})
	}
	if categoryID > 0 {
		q = q.Where(&Project{CategoryID: categoryID})
	}
	if len(statuses) > 0 {
		q = q.Where("status IN (?)", statuses)
	}

	err = q.Count(&total).Error
	if err != nil {
		return
	}

	//if total is 0 then do not to search projects
	if total == 0 {
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
	//if there are no projects, there is nothing to do
	if len(ps) == 0 {
		return nil
	}

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

//
// UserMining
//

//SetUserMiningCredential generate a new password, insert or update record with it, and return a generated password
func (s *DBStore) SetUserMiningCredential(userID uint, login string) (pass string, err error) {
	pass, err = password.Generate(12, 4, 4, false, true)
	if err != nil {
		err = fmt.Errorf("failed to generate a password: %v", err)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		err = fmt.Errorf("failed to generate a password hash: %v", err)
		return
	}

	var umc = UserMiningCredential{
		UserID:       userID,
		Login:        login,
		PasswordHash: hash,
	}
	err = s.gdb.Where(UserMiningCredential{UserID: userID}).Assign(umc).FirstOrCreate(&umc).Error
	if err != nil {
		err = fmt.Errorf("insert or update failed: %v", err)
	}

	return
}

func (s *DBStore) SetUserMiningProject(userID uint, projectID uint) error {
	var ump = UserMiningProject{
		UserID:    userID,
		ProjectID: projectID,
		UpdatedAt: time.Now(),
	}
	return s.gdb.Where(UserMiningProject{UserID: userID}).Assign(ump).FirstOrCreate(&ump).Error
}

func (s *DBStore) GetUserMiningProject(userID uint) (ump UserMiningProject, err error) {
	err = s.gdb.Take(&ump, UserMiningProject{UserID: userID}).Error
	return
}

func (s *DBStore) GetMinedByUser(projectID uint, userID uint) (balance decimal.Decimal, err error) {
	u, err := s.GetUserByID(userID)
	if err != nil {
		return balance, err
	}

	var b Balance
	err = s.gdb.Take(&b, Balance{ProjectID: projectID, Address: u.EthAddress}).Error
	return b.Amount, err
}
