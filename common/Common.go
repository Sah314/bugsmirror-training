package common

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"strconv"
)

func GenerateUniqueID() string {
	IdCounter++
	return strconv.Itoa(IdCounter)
}
func GenerateSecretKey() string {
	id := uuid.New()
	return id.String()
}

// This is the function which generates the unique id for a playlist which is used delete playlist by ID function
func GeneratePlaylistID() string {
	PlaylistID++
	return fmt.Sprintf("PL%d", PlaylistID)
}

// This function helps me in generating a unique song id to perform add song delete song
func GenerateSongID() string {
	SongID++
	return fmt.Sprintf("SN%d", SongID)
}

func EncodeToJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		return
	}
}
