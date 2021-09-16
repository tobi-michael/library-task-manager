package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strings"
	"time"
)
const (
	DbName = "library"
	TaskCollection = "tasks"
	BookCollection = "shenking books"

	jwtSecret = "secretname"
)

type User struct {
	ID       string `json:"id" bson:"id"`
	Name     string `json:"name" bson:"name"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"-,omitempty" bson:"password"`
	Ts          time.Time `json:"timestamp" bson:"timestamp"`
}

type Task struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Age         string    `json:"age"`
	Ts          time.Time `json:"timestamp"`
}

type Claims struct {
	UserId string `json:"user_id"`
	jwt.StandardClaims
}

var dbClient *mongo.Client

func main() {
	// connect to the database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("Could not connect to the db: %v\n", err)
	}

	dbClient = client
	err = dbClient.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatalf("MOngo db not available: %v\n", err)
	}

	// create a new gin router
	router := gin.Default()

	// define a single endpoint
	router.GET("/", welcomeHandler)

	// CRUD enpoints for data

	// create
	router.POST("/createTask", createTaskHandler)

	// retrieve
	router.GET("/getTask/:id", getSingleTaskHandler)

	router.GET("/getUsers", getAllUserHandler)

	router.GET("/getTasks", getAllTasksHandler)

	// update
	router.PATCH("/updateTask/:id", updateTaskHandler)

	// delete
	router.DELETE("/deleteTask/:name", deleteTaskHandler)

	router.POST("/login", loginHandler)

	router.POST("/signup", signupHandler)

	// run the server on the port 3000
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	_ = router.Run(":" + port)
}

func welcomeHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "welcome to task manager API",
	})
}

func createTaskHandler(c *gin.Context) {
	// create task for a specific user

	// get jwt token from request
	authorization := c.Request.Header.Get("Authorization")
	fmt.Println(authorization)

	jwtToken := ""
	sp := strings.Split(authorization, " ")
	if len(sp) > 1 {
		jwtToken = sp[1]
	}


	// decode token to get claims
	claims := &Claims{}
	keyFunc := func(token *jwt.Token) (i interface{}, e error) {
		return []byte(jwtSecret), nil
	}

	token, err := jwt.ParseWithClaims(jwtToken, claims, keyFunc)
	if !token.Valid {
		c.JSON(400, gin.H{
			"error": "invalid jwt token",
		})
		return
	}

	var taskReq Task

	err = c.ShouldBindJSON(&taskReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	// generate task id
	taskId := uuid.NewV4().String()

	task := Task{
		ID: taskId,
		Name: taskReq.Name,
		Age : taskReq.Age ,
		Ts: time.Now(),
	}

	_, err = dbClient.Database(DbName).Collection(TaskCollection).InsertOne(context.Background(), task)
	if err != nil {
		fmt.Println("error saving task", err)
		//	if saving ws not successful
		c.JSON(500, gin.H{
			"error": "Could not process request, could not save task",
		})
		return
	}
	c.JSON(200, gin.H{
		"message": "succesfully created task",
		"data":    task,
	})
}

func getSingleTaskHandler(c *gin.Context) {
	taskId := c.Param("id")

	var task Task
	query := bson.M{
		"id": taskId,
	}
	err := dbClient.Database(DbName).Collection(TaskCollection).FindOne(context.Background(), query).Decode(&task)

	if err != nil {
		fmt.Println("user not found", err)
		c.JSON(404, gin.H{
			"error": "invalid task id: " + taskId,
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
		"data":    task,
	})
}

func getAllUserHandler(c *gin.Context) {
	var users []User

	cursor, err := dbClient.Database(DbName).Collection(BookCollection).Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could not get users",
		})
		return
	}

	err = cursor.All(context.Background(), &users)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could not get users",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
		"data":    users,
	})
}

func getAllTasksHandler(c *gin.Context) {
	// get jwt token from request
	authorization := c.Request.Header.Get("Authorization")
	if authorization == "" {
		c.JSON(401, gin.H{
			"error": "auth token required",
		})
		return
	}

	jwtToken := ""
	sp := strings.Split(authorization, " ")
	if len(sp) > 1 {
		jwtToken = sp[1]
	}


	// decode token to get claims
	claims := &Claims{}
	keyFunc := func(token *jwt.Token) (i interface{}, e error) {
		return []byte(jwtSecret), nil
	}

	token, err := jwt.ParseWithClaims(jwtToken, claims, keyFunc)
	if !token.Valid {
		c.JSON(401, gin.H{
			"error": "invalid jwt token",
		})
		return
	}

	// edit to get only tasks for a specific user
	var tasks []Task

	query := bson.M{
		"owner": claims.UserId,
	}
	cursor, err := dbClient.Database(DbName).Collection(TaskCollection).Find(context.Background(), query)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could get tasks",
		})
		return
	}

	err = cursor.All(context.Background(), &tasks)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could get tasks",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
		"data":    tasks,
	})
}

func updateTaskHandler(c *gin.Context) {
	// get the value passed from the client
	taskId := c.Param("id")

	// creating an empty object to store request data
	var task Task

	// gets the user data that was sent from the client
	// fills up our empty user object with the sent data
	err := c.ShouldBindJSON(&task)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}
	filterQuery := bson.M{
		"id": taskId,
	}

	updateQuery := bson.M{
		"$set": bson.M{
			"name":  task.Name,
			"age":   task.Age ,
		},
	}

	_, err = dbClient.Database(DbName).Collection(TaskCollection).UpdateOne(context.Background(), filterQuery, updateQuery)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could not update task",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "Task updated!",
	})
}

func deleteTaskHandler(c *gin.Context) {
	// get the value passed from the client
	taskId := c.Param("id")

	query := bson.M{
		"id": taskId,
	}
	_, err := dbClient.Database(DbName).Collection(TaskCollection).DeleteOne(context.Background(), query)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could not delete task",
		})
		return
	}
	c.JSON(200, gin.H{
		"message": "Task deleted!",
	})
}

func loginHandler(c *gin.Context) {
	loginReq :=  struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	err := c.ShouldBindJSON(&loginReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	var user User
	query := bson.M{
		"email": loginReq.Email,
	}
	err = dbClient.Database(DbName).Collection(BookCollection).FindOne(context.Background(), query).Decode(&user)
	if err != nil {
		fmt.Printf("error gettinng user from db: %v\n", err)
		c.JSON(500, gin.H{
			"error": "Could not process request, could get user",
		})
		return
	}

	// if found compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		fmt.Printf("error validating password: %v\n", err)
		c.JSON(500, gin.H{
			"error": "Invalid login details",
		})
		return
	}

	// create and return a jwt token
	// claims are the data that you want to store inside the jwt token
	// so whenever someone gives you a token you can decode it and get back this same claims
	claims := &Claims{
		UserId: user.ID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	// generate jwt token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := token.SignedString([]byte(jwtSecret))

	c.JSON(200, gin.H{
		"message": "sign up successful",
		"token": jwtTokenString,
		"data":    user,
	})
}

func signupHandler(c *gin.Context) {
	type SignupRequest struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var signupReq SignupRequest

	err := c.ShouldBindJSON(&signupReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	query := bson.M{
		"email": signupReq.Email,
	}

	// search for duplicate users by email
	count, err := dbClient.Database(DbName).Collection(BookCollection).CountDocuments(context.Background(), query)
	if err != nil {
		fmt.Println("error searching for user: ", err)

		c.JSON(500, gin.H{
			"error": "Could not process request, please try again later",
		})
		return
	}

	// if the count is greater than zero that means a user exists already with that email
	if count > 0 {
		c.JSON(500, gin.H{
			"error": "Email already exits, please use a different email",
		})
		return
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(signupReq.Password), bcrypt.DefaultCost)
	hashPassword := string(bytes)

	// generate user id
	userId := uuid.NewV4().String()

	user := User{
		ID: userId,
		Name: signupReq.Name,
		Email: signupReq.Email,
		Password: hashPassword,
		Ts: time.Now(),
	}

	// store the users data
	_, err = dbClient.Database(DbName).Collection(BookCollection).InsertOne(context.Background(), user)
	if err != nil {
		fmt.Println("error saving user", err)
		//	if saving ws not successful
		c.JSON(500, gin.H{
			"error": "Could not process request, could not save user",
		})
		return
	}

	// claims are the data that you want to store inside the jwt token
	// so whenever someone gives you a token you can decode it and get back this same claims
	claims := &Claims{
		UserId: user.ID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	// generate jwt token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := token.SignedString([]byte(jwtSecret))

	c.JSON(200, gin.H{
		"message": "sign up successful",
		"token": jwtTokenString,
		"data":    user,
	})
}