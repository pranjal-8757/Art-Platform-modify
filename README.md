⚙️ Installation & Setup

 !! Follow the steps below to set up the project locally.

1️⃣ Clone the Repository
-> git clone https://github.com/your-username/your-repo-name.git
-> cd your-repo-name

2️⃣ Backend Setup

Navigate to the backend directory and install dependencies:

-> cd backend
-> npm install

🔐 Environment Configuration

Create a .env file in the backend directory and add the following environment variables:

   PORT=5000
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret_key


⚠️ Note: Ensure your MongoDB instance is running and the connection string is valid.

▶️ Start the Backend Server
-> npm start


3️⃣ Frontend Setup (Optional)

If the project includes a frontend application, follow these steps:

-> cd frontend
-> npm install
-> npm start


The frontend application will run on http://localhost:3000
 by default.
