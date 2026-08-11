package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var collection *mongo.Collection
var coll *mongo.Collection

type rec struct {
	ID      bson.ObjectID `json:"id" bson:"_id,omitempty"`
	UseName string        `json:"useName" bson:"useName"`
	Name    string        `json:"name" bson:"name"`
	Date    string        `json:"date" bson:"date"`
	ActDate int           `json:"actDate" bson:"actDate"`
	Record  string        `json:"record" bson:"record"`
	Owed    float64       `json:"owed" bson:"owed"`
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

func loadData(write http.ResponseWriter, read *http.Request) {
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
	var vale []rec
	var vales Cust
	namee := read.URL.Query().Get("name")
	if namee == "" {
		write.WriteHeader(http.StatusBadRequest)
		return
	}
	name := strings.Split(namee, "_")[0]
	token := strings.Split(namee, "_")[1]
	err := collection.FindOne(read.Context(), bson.M{"useName": name}).Decode(&vales)
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
	if token != vales.Token {
		write.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(write).Encode(map[string]string{"err": "Unable to authorise user. Please try again."})
		return
	}
	date := time.Now().UnixMilli()
	valeo := (int64(date) - int64(vales.PayDate)) / 86400000
	if valeo >= int64(vales.IsPaid) {
		write.WriteHeader(http.StatusLocked)
		json.NewEncoder(write).Encode(map[string]string{"err": "Your package has expired! Buy another package to have access to our services."})

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
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Error retrieving data! Please try again."})
		return
	}
	write.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(write).Encode(vale)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor internet connection! Please try again."})
		return
	}
}

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
	vim, err := bcrypt.GenerateFromPassword([]byte(vex.Password), 12)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "Poor internet connection! Please try again."})
		return
	}
	token := makeToken(vex.User, read)
	err = collection.FindOne(read.Context(), bson.M{"useName": vex.User}).Decode(&vexe)
	if err == nil {
		write.WriteHeader(http.StatusExpectationFailed)
		json.NewEncoder(write).Encode(map[string]string{"err": "The Inputted username already exists. If trying to login, click login instead."})
		return
	}
	saves := Cust{
		UseName:  vex.User,
		RealName: vex.Name,
		IsPaid:   7,
		Password: string(vim),
		PayDate:  int64(time.Now().UnixMilli()),
		Token:    token,
		Exp:      int64(time.Now().UnixMilli() + 86400000),
	}
	_, err = collection.InsertOne(read.Context(), saves)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please try again"})
		return
	}
	write.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success"})
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured. Please try again"})
		return
	}
}
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
	err = json.NewEncoder(write).Encode(map[string]string{"token": token})
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

	vals := read.URL.Query().Get("val")
	if vals == "" {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid Data! Input proper data."})
		return
	}
	id, erk := strconv.ParseInt(strings.Split(vals, "_")[0], 10, 10)
	token := strings.Split(vals, "_")[1]
	name := strings.Split(vals, "_")[2]
	key := makeToken(name, read)
	if erk != nil {
		write.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(write).Encode(map[string]string{"err": "Invalid Data! Input proper data."})
		return
	}
	if key != token {
		write.WriteHeader(http.StatusConflict)
		json.NewEncoder(write).Encode(map[string]string{"err": "We were unable to authorise you. Please try again"})
		return
	}
	_, err := coll.DeleteOne(read.Context(), bson.M{"actDate": id})
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
	err = json.NewEncoder(write).Encode(map[string]string{"message": "Success"})
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(write).Encode(map[string]string{"err": "An error occured! please try again."})
		return
	}
}

func makeToken(val string, read *http.Request) string {
	const words = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-`"
	var cont string
	var pes Cust
	err := collection.FindOne(read.Context(), bson.M{"useName": val}).Decode(&pes)
	if err != nil {
		return "Invalid"
	}
	if int64(time.Now().UnixMilli()) < pes.Exp {
		return pes.Token
	}
	for i := 0; i < 20; i++ {
		idx := rand.Intn(len(words))
		cont += string(words[idx])
	}
	_, err = collection.UpdateOne(read.Context(), bson.M{"useName": val}, bson.M{"$set": bson.M{"token": cont, "exp": int64(time.Now().UnixMilli() + 86400000)}})
	if err != nil {
		return "Error making token"
	}
	return cont
}
func main() {
	var client *mongo.Client
	client, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("MONGO")))
	if err != nil {
		log.Fatal(err)
	}
	rand.Seed(time.Now().UnixNano())
	defer client.Disconnect(context.TODO())

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	collection = client.Database("shop").Collection("records")
	coll = client.Database("shop-records").Collection("persons")

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
