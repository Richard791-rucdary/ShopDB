package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

//Definition of global variables and structs.

var collection *mongo.Collection
var coll *mongo.Collection

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
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	write.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	ctx, cancel := context.WithTimeout(read.Context(), 40*time.Second)
	defer cancel()
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
	token := read.Header.Get("Authorization")
	compareToken := makeToken(name, ctx)
	err = collection.FindOne(ctx, bson.M{"useName": name}).Decode(&vales)

	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

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

	cursor, err := coll.Find(ctx, bson.M{"useName": name})

	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

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
	ctx, cancel := context.WithTimeout(read.Context(), 40*time.Second)
	defer cancel()
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
	if len(vex.User) != 7 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Input a valid username"})
		return
	}

	if len(vex.Name) > 30 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Name is too long! please reduce"})
		return
	}

	if len(vex.Password) > 20 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Please input a short password u can remember."})
		return
	}

	err = collection.FindOne(ctx, bson.M{"useName": vex.User}).Decode(&vexe)

	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

	if err == nil {
		write.WriteHeader(http.StatusExpectationFailed)
		json.NewEncoder(write).Encode(map[string]string{"err": "The Inputted username already exists. If trying to login, click login instead."})
		return
	}

	make := makeToken(vex.User, ctx)
	vim, err := bcrypt.GenerateFromPassword([]byte(vex.Password), 12)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor Internet connection. Please connect to better internet!"})
		return
	}
	saves := Cust{
		UseName:  vex.User,
		RealName: vex.Name,
		IsPaid:   7,
		Password: string(vim),
		PayDate:  int64(time.Now().UnixMilli()),
		Token:    make,
		Exp:      int64(time.Now().UnixMilli() + 86400000),
	}

	_, err = collection.InsertOne(ctx, saves)
	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please try again"})
		return
	}
	vant := makeToken(vex.User, ctx)
	if _, err = collection.UpdateOne(ctx, bson.M{"useName": vex.User}, bson.M{"$set": bson.M{"token": vant}}); err != nil {
		if err == context.DeadlineExceeded {
			write.WriteHeader(http.StatusRequestTimeout)
			json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
			return
		}
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please reload."})
		return
	}

	write.WriteHeader(http.StatusOK)
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success"})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor Internet connection. Please check your internet."})
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
	ctx, cancel := context.WithTimeout(read.Context(), 40*time.Second)
	defer cancel()
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

	err = collection.FindOne(ctx, bson.M{"useName": vex.User}).Decode(&vexer)

	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

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
	token := makeToken(vex.User, ctx)

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

func delete(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	ctx, cancel := context.WithTimeout(read.Context(), 40*time.Second)
	defer cancel()
	type reco struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	var ort reco
	err := json.NewDecoder(read.Body).Decode(&ort)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid Data! Input proper data."})
		return
	}

	key := makeToken(ort.Name, ctx)
	token := read.Header.Get("Authorization")
	if key != token {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you. Please try again"})
		return
	}

	id, err := bson.ObjectIDFromHex(ort.ID)

	if err != nil {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise your customer ID! please try again"})
		return
	}

	_, err = coll.DeleteOne(ctx, bson.M{"_id": id})

	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! Please try again."})
		return
	}
	write.WriteHeader(http.StatusOK)
	json.NewEncoder(write).Encode(map[string]string{"message": "Success deleting data."})
}

func save(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	ctx, cancel := context.WithTimeout(read.Context(), 40*time.Second)
	defer cancel()
	var sav rec

	err := json.NewDecoder(read.Body).Decode(&sav)

	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid data! please input real data."})
		return
	}

	if len(sav.Record) > 1000 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Record is too long!"})
		return
	}
	if len(sav.Name) > 30 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Customer name is too long!"})
		return
	}

	if sav.Owed > 500000000000 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Amount is too huge"})
		return
	}

	token := read.Header.Get("Authorization")

	if token == "" {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you! please try again."})
		return
	}

	var vet Cust

	if ert := collection.FindOne(ctx, bson.M{"token": token}).Decode(&vet); ert != nil {
		if err == context.DeadlineExceeded {
			write.WriteHeader(http.StatusRequestTimeout)
			json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
			return
		}
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you! please try again."})
		return
	}

	_, err = coll.InsertOne(ctx, sav)
	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! please try again."})
		return
	}

	write.WriteHeader(http.StatusOK)
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success"})

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! please try again."})
		return
	}
}

// Make token part
func makeToken(val string, ctx context.Context) string {
	const words = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-`"
	var pes Cust

	err := collection.FindOne(ctx, bson.M{"useName": val}).Decode(&pes)
	if err == context.DeadlineExceeded {
		return "Request timed out"
	}
	if err != nil {
		return "Invalid"
	}

	if int64(time.Now().UnixMilli()) < pes.Exp {
		return pes.Token
	}

	var cont string
	for i := 0; i < 20; i++ {
		mad := big.NewInt(61)
		n, err := rand.Int(rand.Reader, mad)
		if err != nil {
			i--
		}
		ert := int(n.Int64())
		cont += string(words[ert])
	}
	_, err = collection.UpdateOne(ctx, bson.M{"useName": val}, bson.M{"$set": bson.M{"token": cont, "exp": int64(time.Now().UnixMilli() + 86400000)}})

	if err == context.DeadlineExceeded {
		return "Request timed out."
	}

	if err != nil {
		return "Error making token"
	}

	return cont
}

func updateMsg(write http.ResponseWriter, read *http.Request) {
	write.Header().Set("Access-Control-Allow-Origin", "*")
	write.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	ctx, cancel := context.WithTimeout(read.Context(), 40*time.Second)
	defer cancel()
	token := read.Header.Get("Authorization")
	type user struct {
		Pes   string `json:"pes"`
		ID    string `json:"id"`
		Text  string `json:"text"`
		Total int    `json:"total"`
	}
	var vex user
	err := json.NewDecoder(read.Body).Decode(&vex)
	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid JSON. Input proper JSON!"})
		return
	}

	if token == "" {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "Unable to authorise user. Please try again."})
		return
	}

	compareToken := makeToken(vex.Pes, ctx)
	if token != compareToken {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "Unable to authorise user. Please try again."})
		return
	}

	act, err := bson.ObjectIDFromHex(vex.ID)
	if err != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid record ID."})
		return
	}
	if len(vex.Text) > 1000 || len(vex.Text) == 0 {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Record is too long or too short!"})
		return
	}

	_, err = coll.UpdateOne(ctx, bson.M{"_id": act}, bson.M{"$set": bson.M{"record": vex.Text, "owed": vex.Total}})
	if err == context.DeadlineExceeded {
		write.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(write).Encode(map[string]string{"err": "The request timed out. Please try again!"})
		return
	}

	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor internet Connection. Connect to better internet!"})
		return
	}
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Updating record was a success!"})
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "This method is not allowed"})
		return
	}
}

func welc(write http.ResponseWriter, read *http.Request) {
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
	defer read.Body.Close()
	fmt.Fprintln(write, "Server is online!")
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

	shopIndex := mongo.IndexModel{
		Keys:    bson.M{"useName": 1},
		Options: options.Index().SetUnique(true),
	}
	shopIndex2 := mongo.IndexModel{
		Keys:    bson.M{"id": 1},
		Options: options.Index().SetUnique(true),
	}

	collection.Indexes().CreateOne(context.TODO(), shopIndex)
	coll.Indexes().CreateOne(context.TODO(), shopIndex)
	coll.Indexes().CreateOne(context.TODO(), shopIndex2)

	http.HandleFunc("/signup", signUp)
	http.HandleFunc("/login", logIn)
	http.HandleFunc("/load", loadData)
	http.HandleFunc("/pay", retPay)
	http.HandleFunc("/save", save)
	http.HandleFunc("/del", delete)
	http.HandleFunc("/upd", updateMsg)
	http.HandleFunc("/", welc)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.ListenAndServe(":"+port, nil)
}
