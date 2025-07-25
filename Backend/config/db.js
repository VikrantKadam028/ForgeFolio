import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();
const db = mongoose.connect(process.env.MONGODB_URI,{
    dbname:"ForgeFolio"
}).then(()=>{
    console.log("Mongodb connected!");
}).catch((e)=>{
    console.log("Something went wrong!",e.message);

});
