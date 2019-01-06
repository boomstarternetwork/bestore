package bestore

import (
	"database/sql"
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

func generatePassword() (string, error) {
	return password.Generate(12, 4, 4, false, true)
}

func (s *DBStore) AddAdmin(adminLogin string) (string, error) {
	pswd, err := generatePassword()
	if err != nil {
		return "", errors.New("failed to generate password: " + err.Error())
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pswd), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("failed to hash password: " + err.Error())
	}

	return pswd, s.gdb.Create(&Admin{
		Login:        adminLogin,
		PasswordHash: hash,
	}).Error
}

func (s *DBStore) CheckAdminPassword(adminLogin string,
	adminPassword string) error {
	var a Admin
	err := s.gdb.Where(&Admin{Login: adminLogin}).Take(&a).Error
	if err != nil {
		return err
	}
	return bcrypt.CompareHashAndPassword(a.PasswordHash, []byte(adminPassword))
}

func (s *DBStore) ResetAdminPassword(adminID uint) (string, error) {
	pswd, err := generatePassword()
	if err != nil {
		return "", errors.New("failed to generate password: " + err.Error())
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pswd), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("failed to hash password: " + err.Error())
	}

	return pswd, s.gdb.Model(&Admin{}).
		Where(&Admin{ID: adminID}).
		Update(&Admin{PasswordHash: hash}).
		Error
}

func (s *DBStore) RemoveAdmin(adminID uint) error {
	return s.gdb.Where(&Admin{ID: adminID}).Delete(&Admin{}).Error
}

func (s *DBStore) GetAdmins() ([]Admin, error) {
	var admins []Admin

	err := s.gdb.Order("login ASC").Find(&admins).Error
	if err != nil {
		return nil, err
	}

	for _, a := range admins {
		a.PasswordHash = nil
	}

	return admins, nil
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

func (s DBStore) AddUserAddress(userID uint, coin Coin,
	address string) error {
	return s.gdb.Create(&UserAddress{
		UserID:  userID,
		Coin:    coin,
		Address: address,
	}).Error
}

func (s DBStore) RemoveUserAddress(userID uint, coin Coin,
	address string) error {
	return s.gdb.Where(&UserAddress{
		UserID:  userID,
		Coin:    coin,
		Address: address,
	}).Delete(&UserAddress{}).Error
}

func (s DBStore) GetUserAddresses(userID uint) (addrs []UserAddress,
	err error) {
	err = s.gdb.Where(&UserAddress{UserID: userID}).
		Find(&addrs).
		Error
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
		Status:           Draft,
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

func (s *DBStore) SetProject(p Project) error {
	err := s.checkProjectOwner(p.ID, p.UserID)
	if err != nil {
		return err
	}

	np := Project{
		ID:               p.ID,
		Status:           Draft,
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

	return np
}

func (s *DBStore) GetProjects(limit uint, offset uint, userID uint,
	statuses []ProjectStatus) (ps []Project, total uint, err error) {

	q := s.gdb.Model(&Project{}).
		Where(&Project{UserID: userID}).
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

func (s *DBStore) ProjectsBalances() ([]ProjectBalance, error) {
	var balances []ProjectBalance

	rows, err := s.gdb.DB().Query(`
		SELECT p.id, p.name, b.coin, SUM(b.amount)
		FROM projects AS p
			LEFT JOIN balances AS b
				ON p.id = b.project_id
  		GROUP BY p.id, p.name, b.coin
  		ORDER BY p.name ASC, b.coin ASC;
	`)
	if err != nil {
		return balances, err
	}
	defer rows.Close()

	var (
		projectID   uint
		projectName string
		coinStr     sql.NullString
		amount      sql.NullString
	)

	for rows.Next() {
		err = rows.Scan(&projectID, &projectName, &coinStr, &amount)
		if err != nil {
			return balances, err
		}

		if !coinStr.Valid || !amount.Valid {
			// If balances for project is empty we can get null coin and amount.
			// In that case just add project id and name without coins.
			balances = append(balances, ProjectBalance{
				ProjectID:   projectID,
				ProjectName: projectName,
			})
			continue
		}

		// Use decimal to properly truncate trailing zeros from string.
		amountDec, err := decimal.NewFromString(amount.String)
		if err != nil {
			return balances, err
		}

		coin, err := ParseCoin(coinStr.String)
		if err != nil {
			return balances, err
		}

		if len(balances) == 0 ||
			balances[len(balances)-1].ProjectID != projectID {
			// If this is first project or next project we initing it
			// in balances array.

			balances = append(balances, ProjectBalance{
				ProjectID:   projectID,
				ProjectName: projectName,
				Coins: []CoinAmount{
					{Coin: coin, Amount: amountDec},
				},
			})
		} else {
			// Otherwise, we adding next coin data.
			balances[len(balances)-1].Coins = append(
				balances[len(balances)-1].Coins, CoinAmount{
					Coin: coin, Amount: amountDec})
		}
	}

	return balances, rows.Err()
}

func (s *DBStore) ProjectUsersBalances(projectID uint) (
	[]UserBalance, error) {
	var balances []UserBalance

	rows, err := s.gdb.DB().Query(`
		SELECT u.email, b.coin, SUM(b.amount)
		FROM users AS u
			LEFT JOIN balances AS b
				ON ua.address = b.address
		WHERE b.project_id = $1
		GROUP BY u.email, b.coin
		ORDER BY u.email ASC, b.coin ASC;
	`, projectID)
	if err != nil {
		return balances, err
	}
	defer rows.Close()

	var (
		email   string
		coinStr sql.NullString
		amount  sql.NullString
	)

	for rows.Next() {
		err = rows.Scan(&email, &coinStr, &amount)
		if err != nil {
			return balances, err
		}

		if !coinStr.Valid || !amount.Valid {
			// If balances for user is empty we can get null coin and amount.
			// In that case just add user email without coins.
			balances = append(balances, UserBalance{
				Email: email,
			})
			continue
		}

		// Use decimal to properly truncate trailing zeros from string.
		amountDec, err := decimal.NewFromString(amount.String)
		if err != nil {
			return balances, err
		}

		coin, err := ParseCoin(coinStr.String)
		if err != nil {
			return balances, err
		}

		if len(balances) == 0 || balances[len(balances)-1].Email != email {
			// If this is first user or next user we initing it
			// in balances array.
			balances = append(balances, UserBalance{
				Email: email,
				Coins: []CoinAmount{
					{Coin: coin, Amount: amountDec},
				},
			})
		} else {
			// Otherwise, we adding next coin data.
			balances[len(balances)-1].Coins = append(
				balances[len(balances)-1].Coins,
				CoinAmount{Coin: coin, Amount: amountDec})
		}
	}

	return balances, rows.Err()
}
