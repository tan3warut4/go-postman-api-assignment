package main

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const secretKey = "your_secret_key" // Replace with your actual secret key

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type Product struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Price       int    `json:"price"`
	Description string `json:"description"`
}

type CartItem struct {
	ProductID int `json:"product_id"`
	Quantity  int `json:"quantity"`
}

var (
	users    []User
	products []Product
	carts    map[int][]CartItem
)

func main() {
	r := gin.Default()

	r.POST("/auth/login", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		for _, u := range users {
			if u.Username == user.Username && u.Password == user.Password {
				token := jwt.New(jwt.SigningMethodHS256)
				claims := token.Claims.(jwt.MapClaims)
				claims["id"] = u.ID
				claims["username"] = u.Username
				signedToken, _ := token.SignedString([]byte(secretKey))
				c.JSON(http.StatusOK, gin.H{"token": signedToken})
				return
			}
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	})

	r.Use(func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		userID := int(claims["id"].(float64))
		c.Set("userID", userID)
		c.Next()
	})

	r.GET("/user/profile", func(c *gin.Context) {
		userID := c.MustGet("userID").(int)
		var user User
		for _, u := range users {
			if u.ID == userID {
				user = u
				break
			}
		}
		c.JSON(http.StatusOK, user)
	})

	r.GET("/products", func(c *gin.Context) {
		c.JSON(http.StatusOK, products)
	})

	r.POST("/cart/add", func(c *gin.Context) {
		userID := c.MustGet("userID").(int)
		var cartItem CartItem
		if err := c.ShouldBindJSON(&cartItem); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Implement logic to add the product to the user's cart
		// You may want to validate the product ID and quantity
		// Update the user's cart in the `carts` map
		carts[userID] = append(carts[userID], cartItem)
		fmt.Println(carts)
		c.JSON(http.StatusOK, gin.H{"message": "Product added to cart"})
	})

	r.POST("/cart/checkout", func(c *gin.Context) {
		userID := c.MustGet("userID").(int)
		userCart := carts[userID]

		// Implement logic for the checkout process
		totalPrice := calculateTotalPrice(userCart)
		if !deductItemsFromInventory(userCart) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient stock for one or more items"})
			return
		}

		// Clear the user's cart after successful checkout
		carts[userID] = nil

		// Generate an order confirmation
		orderConfirmation := generateOrderConfirmation(userCart, totalPrice)

		c.JSON(http.StatusOK, gin.H{"message": "Checkout successful", "order_confirmation": orderConfirmation})
	})

	// Initialize data (users, products, carts)
	initializeData()

	r.Run(":8080")
}

func initializeData() {
	// Initialize users, products, and carts (you can add more)
	users = []User{
		{ID: 1, Username: "user1", Password: "password1", Name: "User One"},
		{ID: 2, Username: "user2", Password: "password2", Name: "User Two"},
	}

	products = []Product{
		{ID: 1, Name: "Product 1", Price: 10, Description: "Description 1"},
		{ID: 2, Name: "Product 2", Price: 20, Description: "Description 2"},
	}

	carts = make(map[int][]CartItem)
}

func calculateTotalPrice(cart []CartItem) int {
	totalPrice := 0
	for _, item := range cart {
		product := getProductByID(item.ProductID)
		if product != nil {
			totalPrice += product.Price * item.Quantity
		}
	}
	return totalPrice
}

func getProductByID(productID int) *Product {
	for _, p := range products {
		if p.ID == productID {
			return &p
		}
	}
	return nil
}

func deductItemsFromInventory(cart []CartItem) bool {
	// Implement logic to deduct items from inventory
	// Return false if there is insufficient stock
	// Return true if deduction was successful
	// You may need to update the product inventory in your data structure
	for _, item := range cart {
		product := getProductByID(item.ProductID)
		if product == nil || product.Price*item.Quantity < 0 {
			return false
		}
	}
	return true
}

func generateOrderConfirmation(cart []CartItem, totalPrice int) string {
	confirmation := "Order confirmed. Items in your order:\n"
	for _, item := range cart {
		product := getProductByID(item.ProductID)
		confirmation += fmt.Sprintf("- %s (Quantity: %d, Price: $%d)\n", product.Name, item.Quantity, product.Price)
	}
	confirmation += fmt.Sprintf("Total Price: $%d\n", totalPrice)
	return confirmation
}
