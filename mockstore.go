package bestore

import (
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/mock"
)

type MockStore struct {
	mock.Mock
}

func NewMockStore() *MockStore {
	return &MockStore{}
}

func (ms *MockStore) AddUser(externalID, email, password, name,
	avatarURL string, ethAddress string) (User, error) {
	args := ms.Called(externalID, email, password, name, avatarURL, ethAddress)
	return args.Get(0).(User), args.Error(1)
}

func (ms *MockStore) GetUserByID(userID uint) (User, error) {
	args := ms.Called(userID)
	return args.Get(0).(User), args.Error(1)
}

func (ms *MockStore) GetUserByExternalID(externalID string) (User, error) {
	args := ms.Called(externalID)
	return args.Get(0).(User), args.Error(1)
}

func (ms *MockStore) GetUserByEmail(email string) (User, error) {
	args := ms.Called(email)
	return args.Get(0).(User), args.Error(1)
}

func (ms *MockStore) AuthorizeUser(email string, password string) (User, error) {
	args := ms.Called(email, password)
	return args.Get(0).(User), args.Error(1)
}

func (ms *MockStore) SetUserEmail(userID uint, name string) error {
	args := ms.Called(userID, name)
	return args.Error(0)
}

func (ms *MockStore) SetUserEmailConfirmed(userID uint, confirmed bool) error {
	args := ms.Called(userID, confirmed)
	return args.Error(0)
}

func (ms *MockStore) SetUserPassword(userID uint, password string) error {
	args := ms.Called(userID, password)
	return args.Error(0)
}

func (ms *MockStore) SetUserName(userID uint, name string) error {
	args := ms.Called(userID, name)
	return args.Error(0)
}

func (ms *MockStore) SetUserAvatarURL(userID uint, avatarURL string) error {
	args := ms.Called(userID, avatarURL)
	return args.Error(0)
}

func (ms *MockStore) GetUsers() ([]User, error) {
	args := ms.Called()
	users := args.Get(0)
	if users == nil {
		return nil, args.Error(1)
	}
	return users.([]User), args.Error(1)
}

func (ms *MockStore) CheckProjectCategoryID(categoryID uint) error {
	args := ms.Called(categoryID)
	return args.Error(0)
}

func (ms *MockStore) AddCountry(id uint, name string) error {
	args := ms.Called(id, name)
	return args.Error(0)
}

func (ms *MockStore) GetCountries() ([]Country, error) {
	args := ms.Called()
	cs := args.Get(0)
	if cs == nil {
		return nil, args.Error(1)
	}
	return cs.([]Country), args.Error(1)
}

func (ms *MockStore) AddCity(id uint, countryID uint, name string) error {
	args := ms.Called(id, countryID, name)
	return args.Error(0)
}

func (ms *MockStore) GetCities(countryID uint) ([]City, error) {
	args := ms.Called(countryID)
	cs := args.Get(0)
	if cs == nil {
		return nil, args.Error(1)
	}
	return cs.([]City), args.Error(1)
}

func (ms *MockStore) CheckCityID(cityID uint) error {
	args := ms.Called(cityID)
	return args.Error(0)
}

func (ms *MockStore) GetUserPasswordReset(code string) (UserPasswordReset, error) {
	args := ms.Called(code)
	return args.Get(0).(UserPasswordReset), args.Error(1)
}

func (ms *MockStore) AddUserPasswordReset(userID uint) (UserPasswordReset, error) {
	args := ms.Called(userID)
	return args.Get(0).(UserPasswordReset), args.Error(1)
}

func (ms *MockStore) RemoveUserPasswordReset(code string) error {
	args := ms.Called(code)
	return args.Error(0)
}

func (ms *MockStore) GetUserEmailConfirmation(userID uint) (UserEmailConfirmation, error) {
	args := ms.Called(userID)
	return args.Get(0).(UserEmailConfirmation), args.Error(1)
}

func (ms *MockStore) AddUserEmailConfirmation(userID uint,
	email string) (UserEmailConfirmation, error) {
	args := ms.Called(userID, email)
	return args.Get(0).(UserEmailConfirmation), args.Error(1)
}

func (ms *MockStore) RemoveUserEmailConfirmation(userID uint) error {
	args := ms.Called(userID)
	return args.Error(0)
}

func (ms *MockStore) GetUserKYC(userID uint) (UserKYC, error) {
	args := ms.Called(userID)
	return args.Get(0).(UserKYC), args.Error(1)
}

func (ms *MockStore) SetUserKYC(kyc UserKYC) error {
	args := ms.Called(kyc)
	return args.Error(0)
}

func (ms *MockStore) SetUserMiningCredential(userID uint,
	login string) (string, error) {
	args := ms.Called(userID, login)
	return args.String(0), args.Error(1)
}

func (ms *MockStore) GetUserMiningProject(userID uint) (UserMiningProject,
	error) {
	args := ms.Called(userID)
	return args.Get(0).(UserMiningProject), args.Error(1)
}

func (ms *MockStore) SetUserMiningProject(userID uint, projectID uint) error {
	args := ms.Called(userID, projectID)
	return args.Error(0)
}

func (ms *MockStore) GetUserWithdraw(userID uint) (UserWithdraw, error) {
	args := ms.Called(userID)
	return args.Get(0).(UserWithdraw), args.Error(1)
}

func (ms *MockStore) SetUserWithdraw(userID uint, status OperationStatus,
	amount decimal.Decimal) error {
	args := ms.Called(userID, status, amount)
	return args.Error(0)
}

func (ms *MockStore) RemoveUserWithdraw(userID uint) error {
	args := ms.Called(userID)
	return args.Error(0)
}

func (ms *MockStore) GetProject(projectID uint) (Project, error) {
	args := ms.Called(projectID)
	return args.Get(0).(Project), args.Error(1)
}

func (ms *MockStore) AddProject(p Project) (Project, error) {
	args := ms.Called(p)
	return args.Get(0).(Project), args.Error(1)
}

func (ms *MockStore) SetProject(p Project) (Project, error) {
	args := ms.Called(p)
	return args.Get(0).(Project), args.Error(1)
}

func (ms *MockStore) SetProjectModerationStatus(projectID uint,
	moderationStatus OperationStatus) error {
	args := ms.Called(projectID, moderationStatus)
	return args.Error(0)
}

func (ms *MockStore) GetProjects(limit uint, offset uint, userID uint,
	categoryID uint, statuses []ProjectStatus) ([]Project, uint, error) {
	args := ms.Called()
	projects := args.Get(0)
	count := args.Get(1).(uint)
	if projects == nil {
		return nil, count, args.Error(2)
	}
	return projects.([]Project), count, args.Error(2)
}

func (ms *MockStore) AddProjectCategory(name string) (ProjectCategory, error) {
	args := ms.Called()
	return ProjectCategory{Name: name}, args.Error(1)
}

func (ms *MockStore) GetProjectCategories() ([]ProjectCategory, error) {
	args := ms.Called()
	projects := args.Get(0)
	if projects == nil {
		return nil, args.Error(1)
	}
	return projects.([]ProjectCategory), args.Error(1)
}

func (ms *MockStore) GetMinedByUser(projectID uint,
	userID uint) (decimal.Decimal, error) {
	args := ms.Called(projectID, userID)
	return args.Get(0).(decimal.Decimal), args.Error(1)
}
