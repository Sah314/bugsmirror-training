package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"training/common"
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

	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()
	//Implemented logic to find the user by secret code
	for _, user := range common.Users {
		if user.SecretCode == reqBody.SecretCode {
			common.EncodeToJSON(w, user)
			return
		}
	}
	http.Error(w, "User not found", http.StatusNotFound)
}

func Register(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In register method")
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// parsing the request body
	var reqBody struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()

	// Generate a unique secret code
	secretCode := common.GenerateSecretKey() // after registration this function generates a unique secret key for the user
	user := common.User{
		ID:         common.GenerateUniqueID(),
		SecretCode: secretCode,
		Name:       reqBody.Name,
		Email:      reqBody.Email,
	}

	common.Users[user.ID] = user
	common.EncodeToJSON(w, user)
}

func ViewProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//destructing from request body
	var reqBody struct {
		UserID string `json:"userID"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	common.EncodeToJSON(w, user)
}

func AddSongs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//destructing from request body
	var reqBody struct {
		UserID     string      `json:"userID"`
		PlaylistID string      `json:"playlistID"`
		Song       common.Song `json:"song"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	if !playlistExists {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}

	// here the logic to find user and playlist by the ID
	//var user *models.User
	//var playlist *models.Playlist

	//for i := range users {
	//	for j := range users[i].Playlists {
	//		if users[i].Playlists[j].ID == reqBody.PlaylistID {
	//			user = &users[i]
	//			playlist = &users[i].Playlists[j]
	//			break
	//		}
	//	}
	//}
	//TODO: Generateplaylistid will come below
	reqBody.Song.ID = common.GenerateSongID()
	playlist.Songs[reqBody.Song.ID] = reqBody.Song

	// this function adds the song to the existing playlist
	//reqBody.Song.ID = generateUniqueID()
	//playlist.Songs = append(playlist.Songs, reqBody.Song)

	common.EncodeToJSON(w, playlist)

}

func GetAllSongs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var reqBody struct {
		UserID     string `json:"userID"`
		PlaylistID string `json:"playlistID"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	if !playlistExists {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}
	common.EncodeToJSON(w, playlist.Songs)
}
func CreatePlaylist(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var reqBody struct {
		UserID string `json:"userID"`
		//PlaylistID string      `json:"playlistID"`
		Playlist common.Playlist `json:"playlist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	reqBody.Playlist.ID = common.GeneratePlaylistID()
	user.Playlists[reqBody.Playlist.ID] = reqBody.Playlist
	common.EncodeToJSON(w, user.Playlists)
}

func DeleteSongs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var reqBody struct {
		UserID string `json:"userID"`
		//Playlist models.Playlist `json:"playlist"`
		PlaylistID string `json:"playlistID"`
		SongID     string `json:"songID"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	if !playlistExists {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}
	delete(playlist.Songs, reqBody.SongID)

	common.EncodeToJSON(w, map[string]string{
		"message": common.Successmessage,
	})
}

func DeletePlaylist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, common.InvalidRequest, http.StatusMethodNotAllowed)
		return
	}
	//Todo: make this global
	var reqBody struct {
		UserID     string `json:"userID"`
		PlaylistID string `json:"playlistID"`
		//Playlist models.Playlist `json:"playlist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, common.InvalidRequestbody, http.StatusBadRequest)
		return
	}
	common.UsersLock.Lock()
	defer common.UsersLock.Unlock()
	//Todo: validate if body has user id
	if reqBody.UserID == "" {
		http.Error(w, common.UserIdNotfound, http.StatusBadRequest)
		return
	}

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, common.UserNotfound, http.StatusNotFound)
		return
	}
	//playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	//if !playlistExists{
	//	http.Error(w, "Playlist not found", http.StatusNotFound)
	//	return
	//}

	delete(user.Playlists, reqBody.PlaylistID)
	//Todo: define a global struct for response
	common.EncodeToJSON(w, common.Successmessage)

}

func SongDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//destructing from request body
	var reqBody struct {
		UserID     string `json:"userID"`
		PlaylistID string `json:"playlistID"`
		SongID     string `json:"SongID"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	//models.UsersLock.Lock()
	//defer models.UsersLock.Unlock()

	user, userExists := common.Users[reqBody.UserID]
	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	playlist, playlistExists := user.Playlists[reqBody.PlaylistID]
	if !playlistExists {
		http.Error(w, "Playlist not found", http.StatusNotFound)
		return
	}
	song, songExists := playlist.Songs[reqBody.SongID]
	if !songExists {
		http.Error(w, "Song not found", http.StatusNotFound)
		return
	}
	common.EncodeToJSON(w, song)
}
