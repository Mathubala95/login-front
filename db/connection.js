const mongodb = require("mongodb");
const mongoClient = mongodb.MongoClient;
let connection;
let db;

// DB Connection
let connectDB = async () => {
    let connection = await mongoClient.connect(process.env.DB);
    let db = connection.db("login");
    return db;
}

let closeConnection = async () => {
    if(connection){
        await connection.close();
    }
}

module.exports = {connectDB, closeConnection, connection, db}