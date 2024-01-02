package services

import (
	"encoding/json"
	"net/http"
	"training/common"
	"training/models"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	//parsing from the request body
	var reqBody struct {
		SecretCode string `json:"secretCode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	models.UsersLock.Lock()
	defer models.UsersLock.Unlock()
	//Implemented logic to find the user by secret code
	//TODO optimize this:
	for _, user := range models.Users {
		if user.SecretCode == reqBody.SecretCode {
			common.RespondWithJSON(w, user)
			return
		}
	}

	http.Error(w, "User not found", http.StatusNotFound)

}

func Register(w http.ResponseWriter, r *http.Request) {

}
func EditUser(w http.ResponseWriter, r *http.Request) {

}
func Addsongs(w http.ResponseWriter, r *http.Request) {

}
func CreatePlaylist(w http.ResponseWriter, r *http.Request) {

}
func AddSongs(w http.ResponseWriter, r *http.Request) {

}
func DeleteSongs(w http.ResponseWriter, r *http.Request) {

}
func DeletePlaylist(w http.ResponseWriter, r *http.Request) {

}
func SongDetails(w http.ResponseWriter, r *http.Request) {

}
