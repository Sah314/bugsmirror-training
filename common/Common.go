package common

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func GenerateUniqueID(secretKey string, idCounter int) string {
	idCounter++
	return secretKey + "_" + fmt.Sprint(idCounter)
}

// This is the function which generates the unique id for a playlist which is used delete playlist by ID function
func GeneratePlaylistID(playlistID int) string {
	playlistID++
	return fmt.Sprintf("PL%d", playlistID)
}

// This function helps me in generating a unique song id to perform add song delete song
func GenerateSongID(songID int) string {
	songID++
	return fmt.Sprintf("SN%d", songID)
}

func RespondWithJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
