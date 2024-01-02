package models

import "sync"

type User struct {
	ID         string
	SecretCode string
	Name       string
	Email      string
	Playlists  []Playlist
}

// Playlist represents a playlist's data.
type Playlist struct {
	ID    string
	Songs []Song
}

// Song represents a song's data.
type Song struct {
	ID        string
	Name      string
	Composers string
	MusicURL  string
}

var (
	Users      []User
	UsersLock  sync.Mutex
	IdCounter  = 1
	PlaylistID = 1
	SongID     = 1
)
