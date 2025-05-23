package db

import (
	"main/internal/models"

	"gorm.io/gorm"
)

type UserRepository struct {
	DB *gorm.DB
}

func (repo *UserRepository) CreateUser(user *models.User) error {
	return repo.DB.Table("auth.users").Create(user).Error
}

func (repo *UserRepository) GetUserByResetToken(token string) (*models.User, error) {
	var user models.User
	err := repo.DB.Table("auth.users").Where("reset_token = ?", token).First(&user).Error
	return &user, err
}

func (repo *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := repo.DB.Table("auth.users").Where("email = ?", email).First(&user).Error
	return &user, err
}

func (repo *UserRepository) GetUserByID(id uint) (*models.User, error) {
	var user models.User
	err := repo.DB.Table("auth.users").First(&user, id).Error
	return &user, err
}

func (repo *UserRepository) UpdateUser(user *models.User) error {
	return repo.DB.Table("auth.users").Save(user).Error
}
