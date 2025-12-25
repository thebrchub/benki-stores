package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/shivanand-burli/go-starter-kit/jwt"
	"github.com/shivanand-burli/go-starter-kit/models"
	"github.com/shivanand-burli/go-starter-kit/payment"
	"github.com/shivanand-burli/go-starter-kit/redis"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var stripeService payment.PaymentService

var (
	testPrivateKey string
	testPublicKey  string
)

type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	IsAdmin      bool      `json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
}

type Product struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	UnitPrice   int64     `json:"unit_price"`
	Stock       int       `json:"stock"`
	CreatedAt   time.Time `json:"created_at"`
}

type CartItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Price    int64  `json:"price"`
	Quantity int64  `json:"quantity"`
}

type Cart struct {
	Items []CartItem `json:"items"`
}

type Order struct {
	ID              string            `json:"id"`
	UserID          string            `json:"user_id"`
	TotalAmount     int64             `json:"total_amount"`
	Status          string            `json:"status"`
	StripeSessionID string            `json:"stripe_session_id,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	Items           []OrderItemDetail `json:"items,omitempty"`
}

type OrderItemDetail struct {
	ID          string `json:"id"`
	ProductName string `json:"product_name"`
	Quantity    int    `json:"quantity"`
	UnitPrice   int64  `json:"unit_price"`
}

func initStripe() {
	stripeService = payment.NewStripeService()
}

func genKeyAndSetEnv() {
	// Generate RSA keys for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate private key: " + err.Error())
	}

	// Encode private key to PKCS1 format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	testPrivateKey = string(privateKeyPEM)

	// Encode public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic("failed to marshal public key: " + err.Error())
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	testPublicKey = string(publicKeyPEM)

	os.Setenv("JWT_ISSUER", "test-issuer")
	os.Setenv("ACCESS_TOKEN_TTL", "15m")
	os.Setenv("REFRESH_TOKEN_TTL", "168h") // 7 days
	os.Setenv("JWT_PRIVATE_KEY", testPrivateKey)
	os.Setenv("JWT_PUBLIC_KEY", testPublicKey)
	os.Setenv("REFRESH_SECRET", "test-secret-key-minimum-32-bytes!!")
	os.Setenv("STRIPE_SECRET_KEY", "sk_test_51RYL9g2McuOU4O1mHJQj7bfh88vOEBgBOOurZoCUZqKDTWCnH3aOW3CQe3SvLrKMKiN3bJnpaXd84hAliI88Ptmv00sOSWqYoK")
}

func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Println("Unable to load from .env: ", err)
	} else {
		log.Println("Loaded envs from .env")
	}

	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("unable to load DATABASE_URL from .env")
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	redis.InitCache("benki_cart", "localhost", 6379)

	// Initialize Stripe
	initStripe()

	if err := jwt.Init(); err != nil {
		log.Fatal("Failed to initialize JWT:", err)
	}

	mux := http.NewServeMux()

	if os.Getenv("USE_LOCAL_HTML") == "TRUE" {
		mux.HandleFunc("/", serveHome)
	}
	mux.HandleFunc("/api/auth/signup", handleSignup)
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/products", handleProducts)
	mux.HandleFunc("/api/products/create", authMiddleware(adminMiddleware(handleCreateProduct)))
	mux.HandleFunc("/api/cart", authMiddleware(handleCart))
	mux.HandleFunc("/api/checkout", authMiddleware(handleCheckout))
	mux.HandleFunc("/api/webhook/stripe", handleStripeWebhook)
	mux.HandleFunc("/api/user/profile", authMiddleware(handleUserProfile))
	mux.HandleFunc("/api/user/orders", authMiddleware(handleUserOrders))

	seedData()

	handler := corsMiddleware(mux)

	log.Println("🛍️  Benki Stores running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func initDB() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		is_admin BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS products (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		unit_price BIGINT NOT NULL,
		stock INT DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS orders (
		id VARCHAR(36) PRIMARY KEY,
		user_id VARCHAR(36) REFERENCES users(id),
		total_amount BIGINT NOT NULL,
		status VARCHAR(50) DEFAULT 'pending',
		payment_session_id VARCHAR(255),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS order_items (
		id VARCHAR(36) PRIMARY KEY,
		order_id VARCHAR(36) REFERENCES orders(id),
		product_id VARCHAR(36) REFERENCES products(id),
		product_name VARCHAR(255) NOT NULL,
		quantity INT NOT NULL,
		unit_price BIGINT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := db.Exec(schema)
	return err
}

func seedData() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", "admin@benki.com").Scan(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		_, err := db.Exec(
			"INSERT INTO users (id, name, email, password_hash, is_admin) VALUES ($1, $2, $3, $4, $5)",
			uuid.New().String(), "Admin", "admin@benki.com", string(hash), true,
		)
		if err != nil {
			log.Println("Failed to create admin user:", err)
		} else {
			log.Println("✅ Admin user created: admin@benki.com / admin123")
		}
	}

	db.QueryRow("SELECT COUNT(*) FROM products").Scan(&count)
	if count == 0 {
		products := []struct {
			name        string
			description string
			price       int64
			stock       int
		}{
			{"Premium Headphones", "Wireless noise-canceling headphones with premium sound quality", 12999, 50},
			{"Smart Watch", "Fitness tracker with heart rate monitoring and GPS", 29999, 30},
			{"Laptop Stand", "Ergonomic aluminum laptop stand for better posture", 4999, 100},
			{"Mechanical Keyboard", "RGB mechanical keyboard with custom switches", 15999, 45},
			{"Wireless Mouse", "Precision wireless mouse with ergonomic design", 5999, 80},
			{"Phone Case", "Premium protective case with elegant design", 2999, 200},
			{"USB-C Hub", "7-in-1 USB-C hub with multiple ports", 6999, 60},
			{"Portable Charger", "20000mAh fast charging power bank", 4999, 90},
			{"Bluetooth Speaker", "Waterproof portable speaker with 360° sound", 8999, 70},
			{"Webcam HD", "1080p HD webcam with auto-focus and noise reduction", 9999, 40},
		}

		for _, p := range products {
			_, err := db.Exec(
				"INSERT INTO products (id, name, description, unit_price, stock) VALUES ($1, $2, $3, $4, $5)",
				uuid.New().String(), p.name, p.description, p.price, p.stock,
			)
			if err != nil {
				log.Printf("Failed to seed product %s: %v\n", p.name, err)
			}
		}
		log.Println("✅ Products seeded successfully")
	}
}

func serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "../frontend/index.html")
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "All fields required"})
		return
	}

	var exists bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", req.Email).Scan(&exists)
	if exists {
		respondJSON(w, http.StatusConflict, map[string]string{"error": "Email already registered"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to process password"})
		return
	}

	userID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO users (id, name, email, password_hash) VALUES ($1, $2, $3, $4)",
		userID, req.Name, req.Email, string(hash),
	)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create user"})
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{"message": "User created successfully", "user_id": userID})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	var user User
	err := db.QueryRow(
		"SELECT id, name, email, password_hash, is_admin FROM users WHERE email = $1",
		req.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsAdmin)

	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	claims := map[string]any{
		"user_id":  user.ID,
		"email":    user.Email,
		"name":     user.Name,
		"is_admin": user.IsAdmin,
	}
	accessToken, _, err := jwt.GenerateToken(user.ID, claims)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"token": accessToken,
		"user":  map[string]any{"id": user.ID, "name": user.Name, "email": user.Email, "is_admin": user.IsAdmin},
	})
}

func handleProducts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query("SELECT id, name, description, unit_price, stock FROM products WHERE stock > 0 ORDER BY created_at DESC")
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch products"})
		return
	}
	defer rows.Close()

	products := []Product{}
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.UnitPrice, &p.Stock); err != nil {
			continue
		}
		products = append(products, p)
	}

	respondJSON(w, http.StatusOK, products)
}

func handleCreateProduct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p Product
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	p.ID = uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO products (id, name, description, unit_price, stock) VALUES ($1, $2, $3, $4, $5)",
		p.ID, p.Name, p.Description, p.UnitPrice, p.Stock,
	)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create product"})
		return
	}

	respondJSON(w, http.StatusCreated, p)
}

func handleCart(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	ctx := context.Background()

	if r.Method == http.MethodGet {
		var cart Cart
		found, err := redis.Get(ctx, "cart:"+userID, &cart)
		if err != nil || !found {
			cart = Cart{Items: []CartItem{}}
		}
		respondJSON(w, http.StatusOK, cart)
		return
	}

	if r.Method == http.MethodPost {
		var cart Cart
		if err := json.NewDecoder(r.Body).Decode(&cart); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
			return
		}

		if err := redis.PutWithTTL(ctx, "cart:"+userID, cart, 24*time.Hour); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save cart"})
			return
		}

		respondJSON(w, http.StatusOK, map[string]string{"message": "Cart saved"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleCheckout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)
	email := r.Context().Value("email").(string)

	var req struct {
		Items []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			UnitPrice   int64  `json:"unit_price"`
			Quantity    int64  `json:"quantity"`
			Description string `json:"description"`
		} `json:"items"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	if len(req.Items) == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Cart is empty"})
		return
	}

	orderID := uuid.New().String()
	totalAmount := int64(0)
	for _, item := range req.Items {
		totalAmount += item.UnitPrice * item.Quantity
	}

	_, err := db.Exec(
		"INSERT INTO orders (id, user_id, total_amount, status) VALUES ($1, $2, $3, $4)",
		orderID, userID, totalAmount, "pending",
	)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create order"})
		return
	}

	// Save order items
	for _, item := range req.Items {
		_, err := db.Exec(
			"INSERT INTO order_items (id, order_id, product_id, product_name, quantity, unit_price) VALUES ($1, $2, $3, $4, $5, $6)",
			uuid.New().String(), orderID, item.ID, item.Name, item.Quantity, item.UnitPrice,
		)
		if err != nil {
			log.Printf("Failed to save order item: %v\n", err)
		}
	}

	orderItems := make([]models.OrderItem, len(req.Items))
	for i, item := range req.Items {
		orderItems[i] = models.OrderItem{
			BaseProduct: models.BaseProduct{
				ID:        item.ID,
				Name:      item.Name,
				UnitPrice: item.UnitPrice,
			},
			Quantity: item.Quantity,
		}
	}

	log.Println("r.RequestURI ", r.RequestURI)
	log.Println("r.RemoteAddr ", r.RemoteAddr)
	log.Println("r.Host ", r.Host)

	baseOrder := &models.BaseOrder{
		ID:            orderID,
		Currency:      "usd",
		SuccessURL:    "http://localhost:8080/?payment=success&order_id=" + orderID,
		CancelURL:     "http://localhost:8080/?payment=cancelled",
		CustomerEmail: email,
		Items:         orderItems,
		CustomerId:    userID,
	}

	basePaymentResponse, err := stripeService.CheckoutSession(baseOrder)
	if err != nil {
		log.Println("Failed to create checkout session: ", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create checkout session"})
		return
	}

	_, err = db.Exec(
		`UPDATE orders
     SET payment_session_id = $1
     WHERE id = $2`,
		basePaymentResponse.SessionId,
		basePaymentResponse.OrderId,
	)
	if err != nil {
		http.Error(w, "Failed to update order", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	redis.Remove(ctx, "cart:"+userID)

	respondJSON(w, http.StatusOK, map[string]string{"checkout_url": basePaymentResponse.SessionURL, "order_id": orderID})
}

func handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	signature := r.Header.Get("Stripe-Signature")

	basePaymentResponse, err := stripeService.VerifyPayment(payload, signature)
	if err != nil {
		http.Error(w, "Webhook verification failed", http.StatusBadRequest)
		return
	}

	if basePaymentResponse == nil {
		http.Error(w, "payment response is nil", http.StatusNotFound)
		return
	}

	_, err = db.Exec(
		`UPDATE orders
     SET status = $1
     WHERE id = $2 AND status = 'pending'`,
		string(basePaymentResponse.PaymentStatus),
		basePaymentResponse.OrderId,
	)
	if err != nil {
		http.Error(w, "Failed to update order", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleUserProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	var user User
	err := db.QueryRow(
		"SELECT id, name, email, is_admin, created_at FROM users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Name, &user.Email, &user.IsAdmin, &user.CreatedAt)

	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch profile"})
		return
	}

	respondJSON(w, http.StatusOK, user)
}

func handleUserOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	rows, err := db.Query(
		"SELECT id, total_amount, status, created_at FROM orders WHERE user_id = $1 ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch orders"})
		return
	}
	defer rows.Close()

	orders := []Order{}
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.ID, &o.TotalAmount, &o.Status, &o.CreatedAt); err != nil {
			continue
		}

		// Fetch order items
		itemRows, err := db.Query(
			"SELECT id, product_name, quantity, unit_price FROM order_items WHERE order_id = $1",
			o.ID,
		)
		if err == nil {
			o.Items = []OrderItemDetail{}
			for itemRows.Next() {
				var item OrderItemDetail
				if err := itemRows.Scan(&item.ID, &item.ProductName, &item.Quantity, &item.UnitPrice); err == nil {
					o.Items = append(o.Items, item)
				}
			}
			itemRows.Close()
		}

		orders = append(orders, o)
	}

	respondJSON(w, http.StatusOK, orders)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "No authorization header"})
			return
		}

		claims, err := jwt.VerifyToken(authHeader)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", claims["sub"])
		ctx = context.WithValue(ctx, "email", claims["email"])
		ctx = context.WithValue(ctx, "name", claims["name"])
		ctx = context.WithValue(ctx, "is_admin", claims["is_admin"])

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isAdmin, ok := r.Context().Value("is_admin").(bool)
		if !ok || !isAdmin {
			respondJSON(w, http.StatusForbidden, map[string]string{"error": "Admin access required"})
			return
		}
		next.ServeHTTP(w, r)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
