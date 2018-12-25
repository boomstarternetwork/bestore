package bestore

import (
	"github.com/stretchr/testify/mock"
)

type MockStore struct {
	mock.Mock
}

func NewMockStore() *MockStore {
	return &MockStore{}
}
func (ms *MockStore) AddAdmin(adminLogin string) (string, error) {
	args := ms.Called(adminLogin)
	return args.String(0), args.Error(1)
}
func (ms *MockStore) CheckAdminPassword(adminLogin string, adminPassword string) error {
	args := ms.Called(adminLogin, adminPassword)
	return args.Error(0)
}
func (ms *MockStore) ResetAdminPassword(adminID uint) (string, error) {
	args := ms.Called(adminID)
	return args.String(0), args.Error(1)
}
func (ms *MockStore) RemoveAdmin(adminID uint) error {
	args := ms.Called(adminID)
	return args.Error(0)
}
func (ms *MockStore) GetAdmins() ([]Admin, error) {
	args := ms.Called()
	admins := args.Get(0)
	if admins == nil {
		return nil, args.Error(1)
	}
	return admins.([]Admin), args.Error(1)
}
func (ms *MockStore) AddUser(externalID, email, password, name, avatarURL string) (User, error) {
	args := ms.Called(externalID, email, password, name, avatarURL)
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

func (ms *MockStore) AddUserAddress(userID uint, coin Coin, address string) error {
	args := ms.Called(userID, coin, address)
	return args.Error(0)
}

func (ms *MockStore) RemoveUserAddress(userID uint, coin Coin, address string) error {
	args := ms.Called(userID, coin, address)
	return args.Error(0)
}

func (ms *MockStore) GetUserAddresses(userID uint) ([]UserAddress, error) {
	args := ms.Called(userID)
	uas := args.Get(0)
	if uas == nil {
		return nil, args.Error(1)
	}
	return uas.([]UserAddress), args.Error(1)
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

func (ms *MockStore) GetProject(projectID uint) (Project, error) {
	args := ms.Called(projectID)
	return args.Get(0).(Project), args.Error(1)
}

func (ms *MockStore) AddProject(projectName string) error {
	args := ms.Called(projectName)
	return args.Error(0)
}

func (ms *MockStore) SetProjectName(projectID uint, name string) error {
	args := ms.Called(projectID, name)
	return args.Error(0)
}

func (ms *MockStore) RemoveProject(projectID uint) error {
	args := ms.Called(projectID)
	return args.Error(0)
}

func (ms *MockStore) GetProjects() ([]Project, error) {
	args := ms.Called()
	projects := args.Get(0)
	if projects == nil {
		return nil, args.Error(1)
	}
	return projects.([]Project), args.Error(1)
}

func (ms *MockStore) ProjectsBalances() ([]ProjectBalance, error) {
	args := ms.Called()
	pbs := args.Get(0)
	if pbs == nil {
		return nil, args.Error(1)
	}
	return pbs.([]ProjectBalance), args.Error(1)
}

func (ms *MockStore) ProjectUsersBalances(projectID uint) ([]UserBalance,
	error) {
	args := ms.Called(projectID)
	ubs := args.Get(0)
	if ubs == nil {
		return nil, args.Error(1)
	}
	return ubs.([]UserBalance), args.Error(1)
}
