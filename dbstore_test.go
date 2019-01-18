package bestore

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

const (
	postgresConnStr = "postgres://testing:password@localhost:5432/testing" +
		"?sslmode=disable"
	runMode = "testing"
)

var (
	s      *DBStore
	UserID uint = 1 //rewrite on AddUser
)

func initTestingStore() {
	log.SetFlags(log.Lshortfile)

	var err error
	s, err = NewDBStore(postgresConnStr, runMode)
	if err != nil {
		log.Fatalf("Failed to create %v. Postgres connection string: %s", err, postgresConnStr)
	}
}

func runSQL(filePath string) {
	sql, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	requests := strings.Split(string(sql), ";")

	for _, request := range requests {
		_, err := s.gdb.DB().Exec(request)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func TestMain(m *testing.M) {
	initTestingStore()

	runSQL("cleandb.sql")
	runSQL("createdb.sql")

	os.Exit(m.Run())
}

func Test_DBStore_implementsStore(t *testing.T) {
	//var _ Store = &DBStore{}
	var dbs interface{} = &DBStore{}
	if _, ok := dbs.(Store); !ok {
		t.Error("DBStore type non implemented for the Store interface")
	}
}

func Test_DBStore_AddUser_createSuccess(t *testing.T) {
	u, err := s.AddUser("external-id", "Email", "pswd", "name", "aurl", "0xethereumaddr")
	if !assert.NoError(t, err) {
		return
	}

	//assign to a global user-id
	UserID = u.ID

	assert.Equal(t, "external-id", u.ExternalID)
	assert.Equal(t, "Email", u.Email)
	assert.NotEmpty(t, u.PasswordHash)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)
	assert.Equal(t, "0xethereumaddr", u.EthAddress)

	var users []User

	s.gdb.Model(&User{}).Find(&users)

	if !assert.Len(t, users, 1) {
		return
	}

	assert.Equal(t, "external-id", users[0].ExternalID)
	assert.Equal(t, "Email", users[0].Email)
	assert.NotEmpty(t, users[0].PasswordHash)
	assert.Equal(t, "name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)
}

func Test_DBStore_GetUserByID_success(t *testing.T) {
	u := User{
		Email:        fmt.Sprintf("mail@%d", time.Now().UnixNano()),
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}

	err := s.gdb.Create(&u).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: []byte("password-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	udb, err := s.GetUserByID(u.ID)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, u.Email, udb.Email)
	assert.Equal(t, u.Name, udb.Name)
	assert.Equal(t, u.AvatarURL, udb.AvatarURL)
}

func Test_DBStore_GetUserByID_notFound(t *testing.T) {
	u := &User{
		Email:        "mail_byuserid",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}

	err := s.gdb.Create(u).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserByID(999)
	assert.True(t, NotFound(err))
}

func Test_DBStore_GetUserByExternalID_success(t *testing.T) {
	err := s.gdb.Model(&User{}).Create(&User{
		ExternalID:   "eid",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		ExternalID:   "eid2",
		PasswordHash: []byte("password-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	u, err := s.GetUserByExternalID("eid")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "eid", u.ExternalID)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)
}

func Test_DBStore_GetUser_byExternalID_notFound(t *testing.T) {
	err := s.gdb.Model(&User{}).Create(&User{
		ExternalID:   "eid",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserByExternalID("eid99")

	assert.True(t, NotFound(err))
}

func Test_DBStore_GetUserByEmail_success(t *testing.T) {
	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: []byte("password-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	u, err := s.GetUserByEmail("mail")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "mail", u.Email)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)
}

func Test_DBStore_GetUserByEmail_notFound(t *testing.T) {
	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail_userbyemail",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserByEmail("mail_nonexistent_email")
	t.Log(err == gorm.ErrRecordNotFound)

	assert.True(t, NotFound(err))
}

func Test_DBStore_AuthorizeUser_success(t *testing.T) {
	password := "password"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if !assert.NoError(t, err) {
		return
	}

	password2 := "password2"
	passwordHash2, err := bcrypt.GenerateFromPassword([]byte(password2),
		bcrypt.DefaultCost)
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail_auth0",
		PasswordHash: passwordHash,
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail_auth1",
		PasswordHash: passwordHash2,
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	u, err := s.AuthorizeUser("mail_auth0", password)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "mail_auth0", u.Email)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)
}

func Test_DBStore_AuthorizeUser_wrongEmail(t *testing.T) {
	password := "password"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if !assert.NoError(t, err) {
		return
	}

	password2 := "password2"
	passwordHash2, err := bcrypt.GenerateFromPassword([]byte(password2),
		bcrypt.DefaultCost)
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: passwordHash,
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: passwordHash2,
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.AuthorizeUser("mail3", "password")

	assert.True(t, InvalidEmailOrPassword(err))
}

func Test_DBStore_AuthorizeUser_wrongPassword(t *testing.T) {
	password := "password"

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if !assert.NoError(t, err) {
		return
	}

	s.gdb.Model(&User{}).Create(&User{
		Email:        "mail_auth_wrongpass",
		PasswordHash: passwordHash,
		Name:         "name",
		AvatarURL:    "aurl",
	})

	_, err = s.AuthorizeUser("mail_auth_wrongpass", "password1")

	assert.True(t, InvalidEmailOrPassword(err))
}

func Test_DBStore_SetUserName_success(t *testing.T) {
	newName := "new-name"
	err := s.SetUserName(UserID, newName)
	if !assert.NoError(t, err) {
		return
	}

	var users []User
	s.gdb.Find(&users)
	for _, u := range users {
		if u.ID == UserID && u.Name != newName {
			t.Error("failed to update name for specified user")
		}
		if u.ID != UserID && u.Name == newName {
			t.Error("new name setted for unexpected user")
		}
	}
}

func Test_DBStore_SetUserEmail_success(t *testing.T) {
	newEmail := "new-email-address"
	err := s.SetUserEmail(UserID, newEmail)
	if !assert.NoError(t, err) {
		return
	}

	var users []User
	s.gdb.Find(&users)
	for _, u := range users {
		if u.ID == UserID && u.Email != newEmail {
			t.Error("failed to update email for specified user")
		}
		if u.ID != UserID && u.Email == newEmail {
			t.Error("new email setted for unexpected user")
		}
	}
}

func Test_DBStore_SetUserEmailConfirmed_success(t *testing.T) {
	err := s.SetUserEmailConfirmed(UserID, true)
	if !assert.NoError(t, err) {
		return
	}

	var users []User
	s.gdb.Order("id").Find(&users)
	for _, u := range users {
		if u.ID == UserID && !u.EmailConfirmed {
			t.Error("failed to set email confirmed flag for specified user")
		}
		if u.ID != UserID && u.EmailConfirmed {
			t.Error("email confirmed flag setted for unexpected user")
		}
	}
}

func Test_DBStore_SetUserPassword_success(t *testing.T) {
	newPass := fmt.Sprintf("%x", time.Now().UnixNano())
	err := s.SetUserPassword(UserID, newPass)
	if !assert.NoError(t, err) {
		return
	}

	var users []User
	s.gdb.Find(&users)
	for _, u := range users {
		err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(newPass))
		if u.ID == UserID && err != nil {
			t.Error("failed to set password for specified user")
		}

		if u.ID != UserID && err == nil {
			t.Error("password setted for unexpected user")
		}
	}

}

func Test_DBStore_SetUserAvatarURL_success(t *testing.T) {
	newaurl := "new-avatar-url"
	err := s.SetUserAvatarURL(UserID, newaurl)
	if !assert.NoError(t, err) {
		return
	}

	var users []User
	s.gdb.Model(&User{}).Find(&users)

	for _, u := range users {
		if u.AvatarURL == newaurl && u.ID != UserID {
			t.Error("new avatar url specified for unexpected user")
		}
		if u.AvatarURL != newaurl && u.ID == UserID {
			t.Error("new avatar url not set for specified user")
		}
	}
}

func Test_DBStore_GetUsers_success(t *testing.T) {
	u0 := User{
		Email:        fmt.Sprintf("email@%d", time.Now().UnixNano()),
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}
	u1 := User{
		Email:          fmt.Sprintf("email@%d", time.Now().UnixNano()),
		EmailConfirmed: true,
		PasswordHash:   []byte("password-hash2"),
		Name:           "name2",
		AvatarURL:      "aurl2",
	}

	if err := s.gdb.Create(&u0).Error; !assert.NoError(t, err) {
		return
	}

	if err := s.gdb.Create(&u1).Error; !assert.NoError(t, err) {
		return
	}

	users, err := s.GetUsers()
	if !assert.NoError(t, err) {
		return
	}

	for _, u := range users {
		switch u.ID {
		case u0.ID:
			assert.Equal(t, u.Email, u0.Email)
			assert.False(t, u.EmailConfirmed)
			assert.Equal(t, u.PasswordHash, u0.PasswordHash)
			assert.Equal(t, u.Name, u0.Name)
			assert.Equal(t, u.AvatarURL, u0.AvatarURL)

		case u1.ID:
			assert.Equal(t, u.Email, u1.Email)
			assert.True(t, u.EmailConfirmed)
			assert.Equal(t, u.PasswordHash, u1.PasswordHash)
			assert.Equal(t, u.Name, u1.Name)
			assert.Equal(t, u.AvatarURL, u1.AvatarURL)
		}
	}
}

func Test_DBStore_AddUserEmailConfirmation(t *testing.T) {
	//add user email confirmation record
	ec, err := s.AddUserEmailConfirmation(UserID, "mail")
	if !assert.NoError(t, err) {
		return
	}

	//check equal
	assert.Equal(t, UserID, ec.UserID)
	assert.NotEmpty(t, "code", ec.Code)
	code := ec.Code

	err = s.gdb.Take(&ec, UserEmailConfirmation{UserID: UserID}).Error
	if !assert.NoError(t, err) {
		return
	}

	//check record equal
	assert.Equal(t, UserID, ec.UserID)
	assert.Equal(t, "mail", ec.Email)
	assert.Equal(t, code, ec.Code)

	//update exist record email
	ec, err = s.AddUserEmailConfirmation(UserID, "mail2")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, UserID, ec.UserID)
	assert.Equal(t, "mail2", ec.Email)
	assert.NotEqual(t, code, ec.Code)

	//check records count and
	var ecs []UserEmailConfirmation
	s.gdb.Find(&ecs)
	if !assert.Len(t, ecs, 1) {
		return
	}
}

func Test_DBStore_GetUserEmailConfirmation_notFound(t *testing.T) {
	err := s.gdb.Create(&UserEmailConfirmation{
		UserID: UserID,
		Code:   "asd",
		Email:  "mail1",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserEmailConfirmation(uint(time.Now().UnixNano()))
	assert.True(t, NotFound(err))
}

func Test_DBStore_RemoveUserEmailConfirmation_success(t *testing.T) {
	s.gdb.Create(&UserEmailConfirmation{
		UserID: UserID,
		Code:   "qwe",
		Email:  "mail1",
	}).Create(&UserEmailConfirmation{
		UserID: UserID + 1,
		Code:   "asd",
		Email:  "mail2",
	})

	err := s.RemoveUserEmailConfirmation(UserID + 1)
	if !assert.NoError(t, err) {
		return
	}

	var ecs []UserEmailConfirmation
	s.gdb.Model(&UserEmailConfirmation{}).Find(&ecs)

	for _, ec := range ecs {
		assert.NotEqual(t, ec.UserID, UserID+1)
	}
}

func Test_DBStore_SetUserKYC(t *testing.T) {
	kyc0 := UserKYC{
		UserID:     UserID,
		EthAddress: "0xSomeEthereumAddress",
	}
	kyc1 := UserKYC{
		UserID:     UserID + 1,
		EthAddress: "0xOtherEthereumAddress",
	}
	err := s.SetUserKYC(kyc0)
	assert.NoError(t, err)
	err = s.SetUserKYC(kyc1)
	assert.NoError(t, err)
}

func Test_DBStore_GetUserKYC(t *testing.T) {
	gkyc, err := s.GetUserKYC(UserID)
	assert.NoError(t, err)

	assert.Equal(t, UserID, gkyc.UserID)
	assert.Equal(t, "0xSomeEthereumAddress", gkyc.EthAddress)

	t.Log(gkyc)
}

func Test_DBStore_GetUserKYC_notFound(t *testing.T) {
	_, err := s.GetUserKYC(999)
	assert.Error(t, err)
}

//
// Withdraw
//

func Test_DBStore_SetUserWithdraw(t *testing.T) {
	amount := decimal.New(10, 0)
	err := s.SetUserWithdraw(UserID, InitOS, amount)
	assert.NoError(t, err)

	var uw UserWithdraw
	err = s.gdb.Take(&uw, UserWithdraw{UserID: UserID}).Error
	assert.NoError(t, err)

	assert.Equal(t, UserID, uw.UserID)
	assert.Equal(t, InitOS, uw.Status)
	assert.Equal(t, amount, uw.Amount)

	newamount := amount.Add(amount)
	err = s.SetUserWithdraw(UserID, SuccessOS, newamount)
	assert.NoError(t, err)

	err = s.gdb.Take(&uw, UserWithdraw{UserID: UserID}).Error
	assert.NoError(t, err)

	assert.Equal(t, UserID, uw.UserID)
	assert.Equal(t, SuccessOS, uw.Status)
	assert.Equal(t, newamount, uw.Amount)
}

func Test_DBStore_GetUserWithdraw(t *testing.T) {
	uw, err := s.GetUserWithdraw(UserID)
	assert.NoError(t, err)

	assert.Equal(t, UserID, uw.UserID)
	assert.Equal(t, SuccessOS, uw.Status)
}

func Test_DBStore_GetUserWithdraw_notFound(t *testing.T) {
	_, err := s.GetUserWithdraw(999)
	assert.Error(t, err)
}

func Test_DBStore_RemoveUserWithdraw_statusError(t *testing.T) {
	err := s.SetUserWithdraw(UserID, WIPOS, decimal.New(15, 0))
	assert.NoError(t, err)

	err = s.RemoveUserWithdraw(UserID)
	assert.Error(t, err)
	assert.False(t, gorm.IsRecordNotFoundError(err))
}

func Test_DBStore_RemoveUserWithdraw(t *testing.T) {
	s.SetUserWithdraw(UserID, SuccessOS, decimal.New(15, 0))

	err := s.RemoveUserWithdraw(UserID)
	assert.NoError(t, err)

	var uw UserWithdraw
	err = s.gdb.Take(&uw, UserWithdraw{UserID: UserID}).Error
	assert.True(t, gorm.IsRecordNotFoundError(err))
}

//
// Test Countries
//

var CountryID uint = 1

func Test_DBStore_AddCountry(t *testing.T) {
	name := "test-country"

	err := s.AddCountry(CountryID, name)
	assert.NoError(t, err)

	var c Country
	s.gdb.Take(&c, Country{ID: CountryID})
	assert.Equal(t, name, c.Name)
}

func Test_DBStore_GetCountries(t *testing.T) {
	cs, err := s.GetCountries()
	assert.NoError(t, err)

	assert.Len(t, cs, 1)
}

//
// Test Cities
//

var CityID uint = 1

func Test_DBStore_AddCite(t *testing.T) {
	name := "test-city"

	err := s.AddCity(CityID, CountryID, name)
	assert.NoError(t, err)

	var c City
	s.gdb.Take(&c, City{ID: CityID})
	assert.Equal(t, name, c.Name)
}

func Test_DBStore_GetCities(t *testing.T) {
	cs, err := s.GetCities(CountryID)
	assert.NoError(t, err)

	assert.Len(t, cs, 1)
}

func Test_DBStore_GetCities_notFound(t *testing.T) {
	cs, err := s.GetCities(999)
	assert.NoError(t, err)

	assert.Len(t, cs, 0)
}

func Test_DBStore_CheckCityID(t *testing.T) {
	err := s.CheckCityID(CityID)
	assert.NoError(t, err)

	err = s.CheckCityID(999)
	assert.Error(t, err)
}

//
// Test Projects Categories
//

var (
	projCatName = "test-category"
	cat         ProjectCategory
)

func Test_DBStore_AddProjectCategory(t *testing.T) {
	var err error
	cat, err = s.AddProjectCategory(projCatName)
	assert.NoError(t, err)

	assert.Equal(t, projCatName, cat.Name)
	assert.NotEqual(t, 0, cat.ID)
}

func Test_DBStore_GetProjectCategories(t *testing.T) {
	cats, err := s.GetProjectCategories()
	assert.NoError(t, err)
	assert.Len(t, cats, 1)
}

func Test_DBStore_CheckProjectCategoryID(t *testing.T) {
	err := s.CheckProjectCategoryID(cat.ID)
	assert.NoError(t, err)
}

//
// Test Projects
//

var (
	projectID    uint
	projectTitle = "project-title"
)

func Test_DBStore_AddProject(t *testing.T) {
	p := Project{
		UserID:           UserID,
		Title:            projectTitle,
		ShortDescription: "short-desc",
		CategoryID:       cat.ID,
		CityID:           CityID,
	}
	np, err := s.AddProject(p)
	assert.NoError(t, err)

	assert.Equal(t, p.UserID, np.UserID)
	assert.Equal(t, p.Title, np.Title)
	assert.Equal(t, p.ShortDescription, np.ShortDescription)

	projectID = np.ID
}

func Test_DBStore_GetProject(t *testing.T) {
	p, err := s.GetProject(projectID)
	assert.NoError(t, err)
	assert.Equal(t, projectTitle, p.Title)
}

func Test_DBStore_SetProject(t *testing.T) {
	p := Project{
		ID:               projectID,
		UserID:           UserID,
		Title:            projectTitle,
		ShortDescription: "new-short-desc",
		CategoryID:       cat.ID,
		CityID:           CityID,
	}

	_, err := s.SetProject(p)
	assert.NoError(t, err)

	gp, err := s.GetProject(projectID)
	assert.NoError(t, err)

	assert.Equal(t, p.ShortDescription, gp.ShortDescription)
}

func Test_DBStore_SetProjectModerationStatus(t *testing.T) {
	err := s.SetProjectModerationStatus(projectID, SuccessOS)
	assert.NoError(t, err)

	p, _ := s.GetProject(projectID)
	assert.Equal(t, SuccessOS, p.ModerationStatus)
}

func Test_DBStore_GetProjects(t *testing.T) {
	projs, count, err := s.GetProjects(10, 0, UserID, 0, nil)
	assert.NoError(t, err)

	assert.Equal(t, uint(1), count)
	assert.Len(t, projs, 1)
}

func Test_DBStore_GetProjects_notFound(t *testing.T) {
	projs, count, err := s.GetProjects(10, 0, 999, 0, nil)
	assert.NoError(t, err)

	assert.Equal(t, uint(0), count)
	assert.Len(t, projs, 0)
}

//
// Test User Mining
//

func Test_DBStore_SetUserMiningCredential(t *testing.T) {
	login := "test-mining-login"
	pass0, err := s.SetUserMiningCredential(UserID, login)
	assert.NoError(t, err)

	assert.Len(t, pass0, 12)

	pass1, err := s.SetUserMiningCredential(UserID, login)
	assert.NoError(t, err)

	//check if a new password not equal with a previous
	assert.NotEqual(t, pass0, pass1)
}

func Test_DBStore_SetUserMiningProject(t *testing.T) {
	err := s.SetUserMiningProject(UserID, projectID)
	assert.NoError(t, err)

	var ump UserMiningProject
	s.gdb.Take(&ump, UserMiningProject{UserID: UserID})

	assert.Equal(t, projectID, ump.ProjectID)
}

func Test_DBStore_GetUserMiningProject(t *testing.T) {
	ump, err := s.GetUserMiningProject(UserID)
	assert.NoError(t, err)

	assert.Equal(t, projectID, ump.ProjectID)
	assert.Equal(t, UserID, ump.UserID)
	assert.True(t, ump.UpdatedAt.After(time.Time{}))
}

func Test_DBStore_GetMinedByUser(t *testing.T) {
	amount := decimal.New(10, 0)
	err := s.gdb.Create(&Balance{
		ProjectID: projectID,
		Address:   "0xethereumaddr",
		Amount:    amount,
	}).Error
	assert.NoError(t, err)

	mined, err := s.GetMinedByUser(projectID, UserID)
	assert.NoError(t, err)

	assert.Equal(t, amount, mined)

	newamount := amount.Add(amount)

	s.gdb.Create(&Balance{
		ProjectID: projectID,
		Address:   "0xethereumaddr",
		Amount:    newamount,
	})

	mined, err = s.GetMinedByUser(projectID, UserID)
	assert.NoError(t, err)

	assert.Equal(t, newamount, mined.Add(amount))
}
