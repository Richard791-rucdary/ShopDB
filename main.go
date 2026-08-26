package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/resend/resend-go/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

//Definition of global variables and structs.

var collection *mongo.Collection
var coll *mongo.Collection
var otpCon *mongo.Collection

type rec struct {
	ID      bson.ObjectID `json:"id" bson:"_id,omitempty"`
	UseName string        `json:"useName" bson:"useName"`
	Name    string        `json:"name" bson:"name"`
	Date    string        `json:"date" bson:"date"`
	ActDate string        `json:"actDate" bson:"actDate"`
	Record  string        `json:"record" bson:"record"`
	Owed    float64       `json:"owed" bson:"owed"`
	Time    string        `json:"time" bson:"time"`
}

type Cust struct {
	ID       bson.ObjectID `json:"id" bson:"_id,omitempty"`
	UseName  string        `json:"useName" bson:"useName"`
	RealName string        `json:"realName" bson:"realName"`
	IsPaid   int           `json:"isPaid" bson:"isPaid"`
	Password string        `json:"pass" bson:"pass"`
	PayDate  int64         `json:"payDate" bson:"payDate"`
	Token    string        `json:"token" bson:"token"`
	Exp      int64         `json:"exp" bson:"exp"`
}

// Load user data
func loadData(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	type cus struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}

	var vale []rec
	var vales Cust
	var res cus

	err := json.NewDecoder(read.Body).Decode(&res)
	if err != nil {
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid values!"})
		return
	}

	defer read.Body.Close()

	name := res.Name
	token := res.Token
	compareToken := makeToken(name, read)
	err = collection.FindOne(read.Context(), bson.M{"useName": name}).Decode(&vales)

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Your internet is disconnected! Please Try again"})
		return
	}

	if token == "" {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "Unable to authorise user. Please try again."})
		return
	}

	if token != compareToken {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "Unable to authorise user. Please try again."})
		return
	}

	cursor, err := coll.Find(read.Context(), bson.M{"useName": name})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Error connecting to Database! Please try again."})
		return
	}

	defer cursor.Close(read.Context())

	for cursor.Next(read.Context()) {
		var est rec
		cursor.Decode(&est)
		vale = append(vale, est)
	}

	if err = cursor.Err(); err != nil {
		write.Header().Set("Content-Type", "application/json")
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Error retrieving data! Please try again."})
		return
	}

	write.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(write).Encode(map[string][]rec{"message": vale})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// User Sign-Up
func signUp(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	defer read.Body.Close()

	type users struct {
		User     string `json:"user"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}

	var vex users
	var vexe Cust

	err := json.NewDecoder(read.Body).Decode(&vex)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid data! Please input proper data."})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor internet connection! Please try again."})
		return
	}

	err = collection.FindOne(read.Context(), bson.M{"useName": vex.User}).Decode(&vexe)

	if err == nil {
		write.WriteHeader(http.StatusExpectationFailed)
		json.NewEncoder(write).Encode(map[string]string{"err": "The Inputted e-mail already exists. If trying to login, click login instead."})
		return
	}

	van := genOTP(vex.User, vex.Name, vex.Password)

	write.WriteHeader(http.StatusOK)
	json.NewEncoder(write).Encode(map[string]string{"message": van})
	if err == nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor internet connection. Please check your internet connection."})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor Internet connection. Please check your internet."})
	}
}

// Confirm OTP for user Sign-Up
func confOTP(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	type userp struct {
		User  string    `bson:"user"`
		OTP   string    `bson:"otp"`
		Pass  string    `bson:"pass"`
		Name  string    `bson:"name"`
		Exp   time.Time `bson:"exp"`
		Tries int       `bson:"tries"`
	}

	type OTP struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	var vex userp
	var vexer OTP

	err := json.NewDecoder(read.Body).Decode(&vexer)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid JSON. Please input valid JSON."})
		return
	}

	defer read.Body.Close()

	err = otpCon.FindOne(read.Context(), bson.M{"email": vexer.OTP}).Decode(&vex)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please check ypur internet or input a valid email."})
		return
	}

	if vex.Tries >= 5 {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "You can't try again. Contact customer care for support."})
		return
	}

	if vexer.OTP != vex.OTP {
		write.WriteHeader(http.StatusUnauthorized)
		_, _ = otpCon.UpdateOne(read.Context(), bson.M{"email": vex.User}, bson.M{"$set": bson.M{"tries": vex.Tries + 1}})
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid OTP. you have " + string(5-vex.Tries+1) + " tries left."})
		return
	}

	vim, err := bcrypt.GenerateFromPassword([]byte(vex.Pass), 12)

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor internet connection. Connect to stronger internet!"})
		return
	}

	make := makeToken(vex.User, read)

	saves := Cust{
		UseName:  vex.User,
		RealName: vex.Name,
		IsPaid:   7,
		Password: string(vim),
		PayDate:  int64(time.Now().UnixMilli()),
		Token:    make,
		Exp:      int64(time.Now().UnixMilli() + 86400000),
	}

	_, err = collection.InsertOne(read.Context(), saves)

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please try again"})
		return
	}
	vant := makeToken(vex.User, read)
	if _, err = collection.UpdateOne(read.Context(), bson.M{"useName": vex.User}, bson.M{"$set": bson.M{"token": vant}}); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please reload."})
		return
	}
	write.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(write).Encode(map[string]string{"message": "OTP confirmation was a success"})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please try again"})
		return
	}
}

// User Log-In into account
func logIn(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	defer read.Body.Close()

	type users struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}

	var vex users
	var vexer Cust

	err := json.NewDecoder(read.Body).Decode(&vex)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid data! Input proper data."})
		return
	}

	err = collection.FindOne(read.Context(), bson.M{"useName": vex.User}).Decode(&vexer)

	if err != nil {
		write.WriteHeader(404)
		json.NewEncoder(write).Encode(map[string]string{"err": "User not found. If u want to signup, click signup instead."})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(vexer.Password), []byte(vex.Password))

	if err != nil {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid Password. Try password again"})
		return
	}

	write.Header().Set("Content-Type", "application/json")

	write.WriteHeader(http.StatusOK)
	token := makeToken(vex.User, read)

	err = json.NewEncoder(write).Encode(map[string]string{"token": token, "name": vexer.RealName})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! Please try again."})
		return
	}
}

func retPay(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "GET" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	type Price struct {
		Price  float64 `json:"price"`
		Period string  `json:"period"`
		Days   int     `json:"days"`
	}

	prices := []Price{
		{274.99, "1 week", 7},
		{996.99, "1 month", 30},
		{5498.99, "6 months", 181},
		{10257.99, "1 year", 365},
		{19919.99, "2 years", 732},
	}

	write.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(write).Encode(prices)

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! Please try again."})
		return
	}
}

func regPes(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	defer read.Body.Close()

	type reg struct {
		User string `json:"user"`
		Days int    `json:"days"`
	}

	var res reg

	err := json.NewDecoder(read.Body).Decode(&res)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid data! Please input proper data"})
		return
	}

	filter := bson.M{"useName": res.User}
	update := bson.M{"$set": bson.M{"isPaid": res.Days, "payDate": int64(time.Now().UnixMilli())}}
	result, err := collection.UpdateOne(read.Context(), filter, update)

	if result.MatchedCount == 0 {
		write.WriteHeader(http.StatusConflict)
		json.NewEncoder(write).Encode(map[string]string{"err": "User does not exist!"})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An Error occured! Please try again."})
		return
	}
	write.WriteHeader(http.StatusOK)
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success"})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An Error occured! Please try again."})
		return
	}
}

func delete(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	defer read.Body.Close()

	type reco struct {
		ID    string `json:"id"`
		Token string `json:"token"`
		Name  string `json:"name"`
	}

	var ort reco
	err := json.NewDecoder(read.Body).Decode(&ort)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid Data! Input proper data."})
		return
	}

	key := makeToken(ort.Name, read)

	if key != ort.Token {
		write.WriteHeader(http.StatusConflict)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you. Please try again"})
		return
	}

	id, err := bson.ObjectIDFromHex(ort.ID)

	if err != nil {
		write.WriteHeader(http.StatusConflict)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise your customer ID! please try again"})
		return
	}

	_, err = coll.DeleteOne(read.Context(), bson.M{"_id": id})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! Please try again."})
		return
	}
	write.WriteHeader(http.StatusOK)
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success"})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! Please try again."})
		return
	}
}

func save(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if read.Method == "OPTIONS" {
		write.WriteHeader(http.StatusOK)
		return
	}

	if read.Method != "POST" {
		write.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}

	defer read.Body.Close()

	var sav rec

	err := json.NewDecoder(read.Body).Decode(&sav)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid data! please input real data."})
		return
	}

	token := read.URL.Query().Get("token")

	if token == "" {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you! please try again."})
		return
	}

	var vet Cust

	if ert := collection.FindOne(read.Context(), bson.M{"token": token}).Decode(&vet); ert != nil {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you! please try again."})
		return
	}

	_, err = coll.InsertOne(read.Context(), sav)

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! please try again."})
		return
	}

	write.WriteHeader(http.StatusOK)
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success deleting data."})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! please try again."})
		return
	}
}

func genOTP(val string, name string, pass string) string {
	var otp string
	client := resend.NewClient(os.Getenv("RESEND"))

	n, err := rand.Int(rand.Reader, big.NewInt(900000))

	if err != nil {
		return "failed to generate OTP"
	}

	otp = string(int(n.Int64() + 100000))

	type userp struct {
		User  string `bson:"user"`
		OTP   string `bson:"otp"`
		Pass  string `bson:"pass"`
		Name  string `bson:"name"`
		Exp   int64  `bson:"exp"`
		Tries int    `bson:"tries"`
	}

	rep := userp{
		User:  val,
		OTP:   otp,
		Pass:  pass,
		Name:  name,
		Exp:   time.Now().UnixMilli() + 86400000,
		Tries: 0,
	}

	_, err = otpCon.InsertOne(context.TODO(), rep)

	if err != nil {
		return "Failure Generating Response."
	}

	params := &resend.SendEmailRequest{
		From:    "Jotter <onboarding@resend.dev>",
		To:      []string{val},
		Subject: "User OTP",
		Html:    "<h2>Hello user!</h2><p>Your User OTP is <b>" + otp + "</b>. Use It to create your user account.</p>",
	}

	_, err = client.Emails.Send(params)

	if err != nil {
		return "failed to send"
	}

	return "success"
}

func makeToken(val string, read *http.Request) string {
	rand.Seed(time.Now().UnixNano())
	const words = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-`"
	var pes Cust
	err := collection.FindOne(read.Context(), bson.M{"useName": val}).Decode(&pes)

	if err != nil {
		return "Invalid"
	}

	if int64(time.Now().UnixMilli()) < pes.Exp {
		return pes.Token
	}

	var cont string
	for i := 0; i < 20; i++ {
		cont += string(words[rand.Intn(len(words))])
	}
	_, err = collection.UpdateOne(read.Context(), bson.M{"useName": val}, bson.M{"$set": bson.M{"token": string(cont), "exp": int64(time.Now().UnixMilli() + 86400000)}})

	if err != nil {
		return "Error making token"
	}

	return string(cont)
}

// The main function
func main() {
	var client *mongo.Client
	client, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGO"))) //Create a Mongo Client.
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.TODO())

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	collection = client.Database("shop").Collection("records")
	coll = client.Database("shop-records").Collection("persons")
	otpCon = client.Database("OTP").Collection("vars")

	shopIndex := mongo.IndexModel{
		Keys:    bson.M{"useName": 1},
		Options: options.Index().SetUnique(true),
	}

	collection.Indexes().CreateOne(context.TODO(), shopIndex)
	coll.Indexes().CreateOne(context.TODO(), shopIndex)

	http.HandleFunc("/signup", signUp)
	http.HandleFunc("/login", logIn)
	http.HandleFunc("/load", loadData)
	http.HandleFunc("/pay", retPay)
	http.HandleFunc("/save", save)
	http.HandleFunc("/register", regPes)
	http.HandleFunc("/del", delete)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.ListenAndServe(":"+port, nil)
}
