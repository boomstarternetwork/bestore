package bestore

import (
	"errors"

	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
	AddAdmin(adminLogin string) (string, error)
	CheckAdminPassword(adminLogin string, adminPassword string) error
	ResetAdminPassword(adminID uint) (string, error)
	RemoveAdmin(adminID uint) error
	GetAdmins() ([]Admin, error)

	AddUser(externalID, email, password, name, avatarURL string) (User, error)
	GetUserByID(userID uint) (User, error)
	GetUserByExternalID(externalID string) (User, error)
	GetUserByEmail(email string) (User, error)
	AuthorizeUser(email string, password string) (User, error)
	SetUserEmail(userID uint, name string) error
	SetUserEmailConfirmed(userID uint, confirmed bool) error
	SetUserPassword(userID uint, password string) error
	SetUserName(userID uint, name string) error
	SetUserAvatarURL(userID uint, avatarURL string) error
	GetUsers() ([]User, error)

	AddUserAddress(userID uint, coin Coin, address string) error
	RemoveUserAddress(userID uint, coin Coin, address string) error
	GetUserAddresses(userID uint) ([]UserAddress, error)

	GetUserPasswordReset(code string) (UserPasswordReset, error)
	AddUserPasswordReset(userID uint) (UserPasswordReset, error)
	RemoveUserPasswordReset(code string) error

	GetUserEmailConfirmation(userID uint) (UserEmailConfirmation, error)
	AddUserEmailConfirmation(userID uint, email string) (UserEmailConfirmation,
		error)
	RemoveUserEmailConfirmation(userID uint) error

	GetProject(projectID uint) (Project, error)
	AddProject(projectName string) error
	SetProjectName(projectID uint, name string) error
	RemoveProject(projectID uint) error
	GetProjects() ([]Project, error)

	ProjectsBalances() ([]ProjectBalance, error)
	ProjectUsersBalances(projectID uint) ([]UserBalance, error)
}

func NotFound(err error) bool {
	return err == gorm.ErrRecordNotFound
}

var ErrDuplicateUser = errors.New("try to add duplicate user")

func DuplicateUser(err error) bool {
	return err == ErrDuplicateUser
}

func InvalidLoginOrPassword(err error) bool {
	return NotFound(err) || err == bcrypt.ErrMismatchedHashAndPassword
}

func InvalidEmailOrPassword(err error) bool {
	return NotFound(err) || err == bcrypt.ErrMismatchedHashAndPassword
}
