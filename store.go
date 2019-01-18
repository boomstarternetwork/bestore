package bestore

import (
	"errors"

	"github.com/jinzhu/gorm"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
	AddUser(externalID, email, password, name, avatarURL,
		ethAddress string) (User, error)
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

	GetUserPasswordReset(code string) (UserPasswordReset, error)
	AddUserPasswordReset(userID uint) (UserPasswordReset, error)
	RemoveUserPasswordReset(code string) error

	GetUserEmailConfirmation(userID uint) (UserEmailConfirmation, error)
	AddUserEmailConfirmation(userID uint, email string) (UserEmailConfirmation,
		error)
	RemoveUserEmailConfirmation(userID uint) error

	SetUserKYC(kyc UserKYC) error
	GetUserKYC(userID uint) (UserKYC, error)

	// SetUserWithdraw should error if status is WIP
	SetUserWithdraw(userID uint, status OperationStatus,
		amount decimal.Decimal) error
	GetUserWithdraw(userID uint) (UserWithdraw, error)

	// RemoveUserWithdraw should error if exists and status is not Success or Failure.
	RemoveUserWithdraw(userID uint) error

	AddCountry(id uint, name string) error
	GetCountries() ([]Country, error)

	AddCity(id uint, countryID uint, name string) error
	GetCities(countryID uint) ([]City, error)
	CheckCityID(cityID uint) error

	AddProjectCategory(name string) (ProjectCategory, error)
	GetProjectCategories() ([]ProjectCategory, error)
	CheckProjectCategoryID(categoryID uint) error

	AddProject(p Project) (Project, error)
	GetProject(projectID uint) (Project, error)
	SetProject(p Project) (Project, error)
	SetProjectModerationStatus(projectID uint,
		moderationStatus OperationStatus) error
	GetProjects(limit uint, offset uint, userID uint, categoryID uint,
		statuses []ProjectStatus) ([]Project, uint, error)

	SetUserMiningCredential(userID uint, login string) (string, error)

	SetUserMiningProject(userID uint, projectID uint) error
	GetUserMiningProject(userID uint) (UserMiningProject, error)

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

var ErrUserWithdrawAlreadyInWIP = errors.New(
	"user withdraw already in WIP status")
