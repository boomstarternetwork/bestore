package bestore

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/jinzhu/gorm"

	"golang.org/x/crypto/bcrypt"

	"github.com/stretchr/testify/assert"
)

const (
	postgresConnStr = "postgres://testing:password@localhost:5432/testing" +
		"?sslmode=disable"
	runMode = "testing"
)

var s *DBStore

func initTestingStore() {
	var err error
	s, err = NewDBStore(postgresConnStr, runMode)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Failed to create  %s. Postgres connection string: %s\n",
			err.Error(), postgresConnStr)
		os.Exit(1)
	}
}

func runSQL(t *testing.T, filePath string) {
	sql, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatal(err.Error())
	}

	requests := strings.Split(string(sql), ";")

	for _, request := range requests {
		_, err := s.gdb.DB().Exec(request)
		if err != nil {
			t.Fatal(err.Error())
		}
	}
}

func createTestingTables(t *testing.T) {
	runSQL(t, "createdb.sql")
}

func dropTestingTables(t *testing.T) {
	runSQL(t, "cleandb.sql")
}

func TestMain(m *testing.M) {
	initTestingStore()
	os.Exit(m.Run())
}

func Test_DBStore_implementsStore(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)
	//var _ Store = &DBStore{}
	var dbs interface{} = &DBStore{}
	_, ok := dbs.(Store)
	assert.True(t, ok)
}

func Test_DBStore_AddUser_createSuccess(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	u, err := s.AddUser("external-id", "Email", "pswd", "name", "aurl")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "external-id", u.ExternalID)
	assert.Equal(t, "Email", u.Email)
	assert.NotEmpty(t, u.PasswordHash)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)

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
	createTestingTables(t)
	defer dropTestingTables(t)

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

	u, err := s.GetUserByID(1)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "mail", u.Email)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)
}

func Test_DBStore_GetUserByID_notFound(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserByID(2)

	assert.True(t, NotFound(err))
}

func Test_DBStore_GetUserByExternalID_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

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
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		ExternalID:   "eid",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserByExternalID("eid2")

	assert.True(t, NotFound(err))
}

func Test_DBStore_GetUserByEmail_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

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
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("password-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserByEmail("mail2")
	t.Log(err == gorm.ErrRecordNotFound)

	assert.True(t, NotFound(err))
}

func Test_DBStore_AuthorizeUser_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

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

	u, err := s.AuthorizeUser("mail", "password")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "mail", u.Email)
	assert.Equal(t, "name", u.Name)
	assert.Equal(t, "aurl", u.AvatarURL)
}

func Test_DBStore_AuthorizeUser_wrongEmail(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

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
	createTestingTables(t)
	defer dropTestingTables(t)

	password := "password"

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if !assert.NoError(t, err) {
		return
	}

	s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: passwordHash,
		Name:         "name",
		AvatarURL:    "aurl",
	})

	_, err = s.AuthorizeUser("mail", "password1")

	assert.True(t, InvalidEmailOrPassword(err))
}

func Test_DBStore_SetUserName_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("some-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: []byte("some-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.SetUserName(1, "new-name")
	if !assert.NoError(t, err) {
		return
	}

	var users []User

	s.gdb.Order("id ASC").Find(&users)

	if !assert.Len(t, users, 2) {
		return
	}

	assert.Equal(t, "mail", users[0].Email)
	assert.False(t, users[0].EmailConfirmed)
	assert.Equal(t, []byte("some-hash"), users[0].PasswordHash)
	assert.Equal(t, "new-name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)

	assert.Equal(t, "mail2", users[1].Email)
	assert.False(t, users[1].EmailConfirmed)
	assert.Equal(t, []byte("some-hash2"), users[1].PasswordHash)
	assert.Equal(t, "name2", users[1].Name)
	assert.Equal(t, "aurl2", users[1].AvatarURL)
}

func Test_DBStore_SetUserEmail_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("some-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: []byte("some-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.SetUserEmail(1, "new-mail")
	if !assert.NoError(t, err) {
		return
	}

	var users []User

	s.gdb.Model(&User{}).Order("id").Find(&users)

	if !assert.Len(t, users, 2) {
		return
	}

	assert.Equal(t, "new-mail", users[0].Email)
	assert.False(t, users[0].EmailConfirmed)
	assert.Equal(t, []byte("some-hash"), users[0].PasswordHash)
	assert.Equal(t, "name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)

	assert.Equal(t, "mail2", users[1].Email)
	assert.False(t, users[1].EmailConfirmed)
	assert.Equal(t, []byte("some-hash2"), users[1].PasswordHash)
	assert.Equal(t, "name2", users[1].Name)
	assert.Equal(t, "aurl2", users[1].AvatarURL)
}

func Test_DBStore_SetUserEmailConfirmed_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:          "mail",
		EmailConfirmed: false,
		PasswordHash:   []byte("some-hash"),
		Name:           "name",
		AvatarURL:      "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:          "mail2",
		EmailConfirmed: false,
		PasswordHash:   []byte("some-hash2"),
		Name:           "name2",
		AvatarURL:      "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.SetUserEmailConfirmed(2, true)
	if !assert.NoError(t, err) {
		return
	}

	var users []User

	s.gdb.Model(&User{}).Order("id").Find(&users)

	if !assert.Len(t, users, 2) {
		return
	}

	assert.Equal(t, "mail", users[0].Email)
	assert.False(t, users[0].EmailConfirmed)
	assert.Equal(t, []byte("some-hash"), users[0].PasswordHash)
	assert.Equal(t, "name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)

	assert.Equal(t, "mail2", users[1].Email)
	assert.True(t, users[1].EmailConfirmed)
	assert.Equal(t, []byte("some-hash2"), users[1].PasswordHash)
	assert.Equal(t, "name2", users[1].Name)
	assert.Equal(t, "aurl2", users[1].AvatarURL)
}

func Test_DBStore_SetUserPassword_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("some-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: []byte("some-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.SetUserPassword(1, "password")
	if !assert.NoError(t, err) {
		return
	}

	var users []User

	s.gdb.Order("id ASC").Find(&users)

	if !assert.Len(t, users, 2) {
		return
	}

	assert.Equal(t, "mail", users[0].Email)
	assert.False(t, users[0].EmailConfirmed)
	assert.NotEqual(t, []byte("some-hash"), users[0].PasswordHash)
	assert.Equal(t, "name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)

	assert.Equal(t, "mail2", users[1].Email)
	assert.False(t, users[1].EmailConfirmed)
	assert.Equal(t, []byte("some-hash2"), users[1].PasswordHash)
	assert.Equal(t, "name2", users[1].Name)
	assert.Equal(t, "aurl2", users[1].AvatarURL)
}

func Test_DBStore_SetUserAvatarURL_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&User{}).Create(&User{
		Email:        "mail",
		PasswordHash: []byte("some-hash"),
		Name:         "name",
		AvatarURL:    "aurl",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.gdb.Create(&User{
		Email:        "mail2",
		PasswordHash: []byte("some-hash2"),
		Name:         "name2",
		AvatarURL:    "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	err = s.SetUserAvatarURL(2, "new-aurl2")
	if !assert.NoError(t, err) {
		return
	}

	var users []User

	s.gdb.Model(&User{}).Find(&users)

	if !assert.Len(t, users, 2) {
		return
	}

	assert.Equal(t, "mail", users[0].Email)
	assert.False(t, users[0].EmailConfirmed)
	assert.Equal(t, []byte("some-hash"), users[0].PasswordHash)
	assert.Equal(t, "name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)

	assert.Equal(t, "mail2", users[1].Email)
	assert.False(t, users[1].EmailConfirmed)
	assert.Equal(t, []byte("some-hash2"), users[1].PasswordHash)
	assert.Equal(t, "name2", users[1].Name)
	assert.Equal(t, "new-aurl2", users[1].AvatarURL)
}

func Test_DBStore_GetUsers_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

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
		Email:          "mail2",
		EmailConfirmed: true,
		PasswordHash:   []byte("password-hash2"),
		Name:           "name2",
		AvatarURL:      "aurl2",
	}).Error
	if !assert.NoError(t, err) {
		return
	}

	users, err := s.GetUsers()
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "mail", users[0].Email)
	assert.False(t, users[0].EmailConfirmed)
	assert.Equal(t, []byte("password-hash"), users[0].PasswordHash)
	assert.Equal(t, "name", users[0].Name)
	assert.Equal(t, "aurl", users[0].AvatarURL)

	assert.Equal(t, "mail2", users[1].Email)
	assert.True(t, users[1].EmailConfirmed)
	assert.Equal(t, []byte("password-hash2"), users[1].PasswordHash)
	assert.Equal(t, "name2", users[1].Name)
	assert.Equal(t, "aurl2", users[1].AvatarURL)
}

func Test_DBStore_AddUserEmailConfirmation_createSuccess(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	ec, err := s.AddUserEmailConfirmation(123, "mail")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, uint(123), ec.UserID)
	assert.NotEmpty(t, "name", ec.Code)

	var ecs []UserEmailConfirmation

	s.gdb.Model(&UserEmailConfirmation{}).Find(&ecs)

	if !assert.Len(t, ecs, 1) {
		return
	}

	assert.Equal(t, uint(123), ecs[0].UserID)
	assert.Equal(t, "mail", ecs[0].Email)
	assert.NotEmpty(t, ecs[0].Code)
}

func Test_DBStore_AddUserEmailConfirmation_updateSuccess(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	s.gdb.Model(&UserEmailConfirmation{}).
		Create(&UserEmailConfirmation{
			UserID: 123,
			Code:   "code",
			Email:  "mail1",
		})

	ec, err := s.AddUserEmailConfirmation(123, "mail2")
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, uint(123), ec.UserID)
	assert.Equal(t, "mail2", ec.Email)
	assert.NotEqual(t, "code", ec.Code)

	var ecs []UserEmailConfirmation

	s.gdb.Model(&UserEmailConfirmation{}).Find(&ecs)

	if !assert.Len(t, ecs, 1) {
		return
	}

	assert.Equal(t, uint(123), ecs[0].UserID)
	assert.Equal(t, "mail2", ecs[0].Email)
	assert.NotEqual(t, "code", ecs[0].Code)
}

func Test_DBStore_GetUserEmailConfirmation_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	s.gdb.Model(&UserEmailConfirmation{}).
		Create(&UserEmailConfirmation{
			UserID: 123,
			Code:   "qwe",
			Email:  "mail1",
		}).
		Create(&UserEmailConfirmation{
			UserID: 234,
			Code:   "asd",
			Email:  "mail2",
		})

	ec, err := s.GetUserEmailConfirmation(234)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, uint(234), ec.UserID)
	assert.Equal(t, "asd", ec.Code)
	assert.Equal(t, "mail2", ec.Email)
}

func Test_DBStore_GetUserEmailConfirmation_notFound(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	err := s.gdb.Model(&UserEmailConfirmation{}).
		Create(&UserEmailConfirmation{
			UserID: 234,
			Code:   "asd",
			Email:  "mail1",
		}).Error
	if !assert.NoError(t, err) {
		return
	}

	_, err = s.GetUserEmailConfirmation(123)

	assert.True(t, NotFound(err))
}

func Test_DBStore_RemoveUserEmailConfirmation_success(t *testing.T) {
	createTestingTables(t)
	defer dropTestingTables(t)

	s.gdb.Model(&UserEmailConfirmation{}).
		Create(&UserEmailConfirmation{
			UserID: 123,
			Code:   "qwe",
			Email:  "mail1",
		}).
		Create(&UserEmailConfirmation{
			UserID: 234,
			Code:   "asd",
			Email:  "mail2",
		})

	err := s.RemoveUserEmailConfirmation(234)
	if !assert.NoError(t, err) {
		return
	}

	var ecs []UserEmailConfirmation

	s.gdb.Model(&UserEmailConfirmation{}).Find(&ecs)

	if !assert.Len(t, ecs, 1) {
		return
	}

	assert.Equal(t, uint(123), ecs[0].UserID)
	assert.Equal(t, "qwe", ecs[0].Code)
	assert.Equal(t, "mail1", ecs[0].Email)
}
