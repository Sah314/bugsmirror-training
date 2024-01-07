package common

import "sync"

type User struct {
	ID         string
	SecretCode string
	Name       string
	Email      string
	Playlists  map[string]Playlist
}

// Playlist represents a playlist's data.
type Playlist struct {
	ID    string
	Songs map[string]Song
}
type ReqBody struct {
	UserID     string   `json:"userID"`
	PlaylistID string   `json:"playlistID"`
	SongID     string   `json:"songID"`
	Playlist   Playlist `json:"playlist"`
	Song       Song     `json:"song"`
}
type UserReqBody struct {
	ID         string `json:"id"`
	SecretCode string `json:"secretCode"`
	Name       string `json:"name"`
	Email      string `json:"email"`
}

// Song represents a song's data.
type Song struct {
	ID        string
	Name      string
	Composers string
	MusicURL  string
}

var (
	Users      = make(map[string]User)
	UsersLock  sync.Mutex
	IdCounter  = 1
	PlaylistID = 1
	SongID     = 1
)
