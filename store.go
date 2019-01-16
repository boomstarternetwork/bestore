package bestore

import (
	"errors"

	"github.com/shopspring/decimal"

	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
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

	CheckProjectCategoryID(categoryID uint) error

	AddCountry(id uint, name string) error
	GetCountries() ([]Country, error)

	AddCity(id uint, countryID uint, name string) error
	GetCities(countryID uint) ([]City, error)
	CheckCityID(cityID uint) error

	GetUserPasswordReset(code string) (UserPasswordReset, error)
	AddUserPasswordReset(userID uint) (UserPasswordReset, error)
	RemoveUserPasswordReset(code string) error

	GetUserEmailConfirmation(userID uint) (UserEmailConfirmation, error)
	AddUserEmailConfirmation(userID uint, email string) (UserEmailConfirmation,
		error)
	RemoveUserEmailConfirmation(userID uint) error

	GetUserKYC(userID uint) (UserKYC, error)
	SetUserKYC(kyc UserKYC) error

	SetUserMiningCredential(userID uint, login string) (string, error)

	GetUserMiningProject(userID uint) (UserMiningProject, error)
	SetUserMiningProject(userID uint, projectID uint) error

	GetProject(projectID uint) (Project, error)
	AddProject(p Project) (Project, error)
	SetProject(p Project) (Project, error)
	SetProjectModerationStatus(projectID uint,
		moderationStatus OperationStatus) error
	GetProjects(limit uint, offset uint, userID uint, categoryID uint,
		statuses []ProjectStatus) ([]Project, uint, error)

	GetProjectCategories() ([]ProjectCategory, error)

	GetMinedByUser(projectID uint, userID uint) (decimal.Decimal, error)
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

var ErrInvalidCategoryID = errors.New("invalid category ID")

func InvalidCategoryID(err error) bool {
	return err == ErrInvalidCategoryID
}

var ErrInvalidCityID = errors.New("invalid city ID")

func InvalidCityID(err error) bool {
	return err == ErrInvalidCityID
}

var ErrInvalidProjectOwner = errors.New("invalid project owner")

func InvalidProjectOwner(err error) bool {
	return err == ErrInvalidProjectOwner
}
