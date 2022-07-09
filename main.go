package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

func authorization(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(map[string]string{"message": "success"})
}

func token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(map[string]string{"message": "success"})
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// パラメータ取得
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
	}

	var cur CreateUserRequest
	if err := json.Unmarshal(reqBody, &cur); err != nil {
		log.Println(err.Error())
		json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
	}

	// 環境変数取得
	region := os.Getenv("REGION")
	userPoolID := os.Getenv("USER_POOL_ID")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	// AWS設定
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))

	// ユーザー作成
	input := cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId:        aws.String(userPoolID),
		Username:          aws.String(cur.Username),
		TemporaryPassword: aws.String(cur.Password),
	}
	c := cognitoidentityprovider.New(sess)
	if _, err := c.AdminCreateUser(&input); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error-message": err.Error()})
	}

	// 認証フロー開始（上記作成だけだとメールアドレスの認証ができておらず、後にトークンが取得できないので認証まで行う）
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(*&cur.Username + clientID))
	secretHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	initiateAuthOutput, err := c.AdminInitiateAuth(&cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow:   aws.String("ADMIN_USER_PASSWORD_AUTH"),
		UserPoolId: &userPoolID,
		ClientId:   &clientID,
		AuthParameters: map[string]*string{
			"USERNAME":    &cur.Username,
			"PASSWORD":    &cur.Password,
			"SECRET_HASH": &secretHash,
		},
	})
	if err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]string{"error-message": err.Error()})
	}

	if _, err := c.AdminRespondToAuthChallenge(&cognitoidentityprovider.AdminRespondToAuthChallengeInput{
		UserPoolId:    &userPoolID,
		ClientId:      &clientID,
		ChallengeName: aws.String("NEW_PASSWORD_REQUIRED"),
		ChallengeResponses: map[string]*string{
			"USERNAME":     &cur.Username,
			"NEW_PASSWORD": &cur.Password,
			"SECRET_HASH":  &secretHash,
		},
		Session: initiateAuthOutput.Session,
	}); err != nil {
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]string{"error-message": err.Error()})
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "success"})
}

func main() {
	if err := godotenv.Load(".env"); err != nil {
		fmt.Println(".env load error")
		os.Exit(0)
	}

	r := mux.NewRouter()

	// OIDC API
	r.HandleFunc("/authorize", authorization).Methods("GET")
	r.HandleFunc("/token", token).Methods("GET")

	// TEST API
	r.HandleFunc("/user", createUser).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", r))
}
