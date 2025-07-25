import mongoose from "mongoose";

const db = mongoose.connect("mongodb+srv://vikrantkk2889:clZRES2qrls0b4n9@cluster0.yqonlou.mongodb.net/",{
    dbname:"ForgeFolio"
}).then(()=>{
    console.log("Mongodb connected!");
}).catch((e)=>{
    console.log("Something went wrong!",e.message);

});
