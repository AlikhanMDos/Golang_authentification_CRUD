package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"time"
)

var store = sessions.NewCookieStore([]byte("your-secret-key"))

type PageData struct {
	Username string // Change UserID to Username
}

type Course struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	StartDate   time.Time `json:"startDate"`
	EndDate     time.Time `json:"endDate"`
}

type Student struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	CourseID   int       `json:"courseId"`
	EnrollDate time.Time `json:"enrollDate"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RequestBody struct {
	Course  Course  `json:"course"`
	Student Student `json:"student"`
}

type ResponseBody struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

var courses []Course
var students []Student

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	http.Handle("/templates/", http.StripPrefix("/templates/", http.FileServer(http.Dir("./templates/"))))

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/courses", handleCourseRequest)
	http.HandleFunc("/students", handleStudentRequest)
	http.HandleFunc("/registration", handleRegistrationPage)
	http.HandleFunc("/login", handleLoginPage)
	http.HandleFunc("/cabinet", handleCabinetPage)

	port := 8080
	fmt.Printf("Server is listening on port %d...\n", port)

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		fmt.Println("Error starting the server:", err)
	}

	log.Println("Сервер запущен на порту :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request, username string, collection *mongo.Collection) error {
	// Delete the user account from the database
	_, err := collection.DeleteOne(context.Background(), bson.M{"username": username})
	return err
}

func handleUpdatePassword(w http.ResponseWriter, r *http.Request, username string, collection *mongo.Collection) error {
	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}

	// Extract the new password and confirmation from the form
	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	// Validate the new password and confirmation
	if newPassword != confirmPassword {
		http.Error(w, "New password and confirmation do not match", http.StatusBadRequest)
		return errors.New("New password and confirmation do not match")
	}

	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return err
	}

	// Update the password in the database
	update := bson.M{"$set": bson.M{"passwordHash": string(hashedNewPassword)}}
	_, err = collection.UpdateOne(context.Background(), bson.M{"username": username}, update)
	if err != nil {
		http.Error(w, "Error updating password", http.StatusInternalServerError)
		return err
	}

	http.Redirect(w, r, "login", http.StatusSeeOther)

	return nil
}

func handleCabinetPage(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling cabinet.html request...")

	// Извлечение имени пользователя из сессии
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	// Подключение к MongoDB Atlas
	clientOptions := options.Client().ApplyURI("mongodb+srv://220727:1234567899@cluster0.authau1.mongodb.net/?retryWrites=true&w=majority")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Проверка подключения к MongoDB
	err = client.Ping(context.Background(), readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	// Получение данных о пользователе из базы данных
	collection := client.Database("Went").Collection("Gone")
	var userData User
	err = collection.FindOne(context.Background(), bson.M{"username": username}).Decode(&userData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Подготовка данных для передачи в шаблон
	data := PageData{
		Username: userData.Username,
	}

	// Check if the form for updating password is submitted
	// Check if the form for updating password or deleting account is submitted
	if r.Method == http.MethodPost {
		// Check the form action parameter to determine the action
		action := r.FormValue("action")

		switch action {
		case "update-password":
			// Handle updating password
			err := handleUpdatePassword(w, r, username, collection)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Redirect to the root page after successful update
			http.Redirect(w, r, "localhost:8080/login", http.StatusSeeOther)
			return
		case "delete-account":
			// Handle deleting account
			err := handleDeleteAccount(w, r, username, collection)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Redirect to the root page after successful deletion
			http.Redirect(w, r, "/registration", http.StatusSeeOther)
			return
		}
	}
	// Отображение страницы кабинета с данными о пользователе
	tmpl, err := template.ParseFiles("templates/cabinet.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, data)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		fmt.Fprintf(w, err.Error())
	}

	tmpl.Execute(w, nil)
}

func handleRegistrationPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Если это GET-запрос, отобразите страницу регистрации
		tmpl, err := template.ParseFiles("templates/registration.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, nil)
	case http.MethodPost:
		// Если это POST-запрос, обработайте данные регистрации
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Генерация хэша пароля
		user := User{
			Username: username,
			Password: password,
		}

		// Подключение к MongoDB Atlas
		clientOptions := options.Client().ApplyURI("mongodb+srv://220727:1234567899@cluster0.authau1.mongodb.net/?retryWrites=true&w=majority")
		client, err := mongo.Connect(context.Background(), clientOptions)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(context.Background())

		// Проверка подключения к MongoDB
		err = client.Ping(context.Background(), readpref.Primary())
		if err != nil {
			log.Fatal(err)
		}

		// Вставка данных пользователя в MongoDB
		collection := client.Database("Went").Collection("Gone")
		_, err = collection.InsertOne(context.Background(), user)
		if err != nil {
			log.Println("Error inserting user into MongoDB:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Отправка успешного ответа
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Регистрация прошла успешно")
	default:
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
	}
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, nil)
	case http.MethodPost:
		// Обработка данных входа
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Подключение к MongoDB Atlas
		clientOptions := options.Client().ApplyURI("mongodb+srv://220727:1234567899@cluster0.authau1.mongodb.net/?retryWrites=true&w=majority")
		client, err := mongo.Connect(context.Background(), clientOptions)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Disconnect(context.Background())

		// Проверка подключения к MongoDB
		err = client.Ping(context.Background(), readpref.Primary())
		if err != nil {
			log.Fatal(err)
		}

		// Поиск пользователя в базе данных по введенному имени пользователя
		collection := client.Database("Went").Collection("Gone")
		var user User
		err = collection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		// Сравнение паролей
		if user.Password != password {
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		// Успешный вход в систему

		// Сохранение имени пользователя в сессии
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["username"] = user.Username // Change userID to username
		session.Save(r, w)

		// Перенаправление на страницу кабинета
		http.Redirect(w, r, "/cabinet", http.StatusSeeOther)
	default:
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
	}
}

func handleCourseRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGetCoursesRequest(w, r)
	case http.MethodPost:
		handlePostCourseRequest(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleStudentRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGetStudentsRequest(w, r)
	case http.MethodPost:
		handlePostStudentRequest(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleGetCoursesRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(courses)
}

func handlePostCourseRequest(w http.ResponseWriter, r *http.Request) {
	var requestBody RequestBody
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestBody)
	if err != nil {
		errorResponse := ResponseBody{
			Status:  "400",
			Message: "Invalid JSON format",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	// Валидация данных
	if requestBody.Course.ID <= 0 || requestBody.Course.Title == "" {
		errorResponse := ResponseBody{
			Status:  "400",
			Message: "Invalid or missing data for the course",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	// Добавляем новый курс
	courses = append(courses, requestBody.Course)

	response := ResponseBody{
		Status:  "success",
		Message: "Course added successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleGetStudentsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(students)
}

func handlePostStudentRequest(w http.ResponseWriter, r *http.Request) {
	var requestBody RequestBody
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestBody)
	if err != nil {
		errorResponse := ResponseBody{
			Status:  "400",
			Message: "Invalid JSON format",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	// Валидация данных
	if requestBody.Student.ID <= 0 || requestBody.Student.Name == "" {
		errorResponse := ResponseBody{
			Status:  "400",
			Message: "Invalid or missing data for the student",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	// Добавляем нового студента
	students = append(students, requestBody.Student)

	response := ResponseBody{
		Status:  "success",
		Message: "Student added successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
