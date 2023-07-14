import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt  from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose.connect("mongodb://127.0.0.1:27017",{
    dbName: "backend",
})
.then(()=>console.log("database connected"))
.catch((e)=> console.log(e));


const userschema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});

const User = mongoose.model("User",userschema); 

const app = express();

//using middlewares 
app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());

// setting up view engine
app.set("view engine","ejs");


const isauthenicated = async (req,res,next)=>{
    const {token} = req.cookies;
    if(token)
    {
        const decoded = jwt.verify(token,"eufwfiwegfuwe");

        req.user = await User.findById(decoded._id);


        next();
    }
    else
    {
        res.redirect("/login");
    }
}

app.get("/",isauthenicated ,(req,res)=>{
    res.render("logout",{name:req.user.name});
});

app.get("/login",(req,res)=>{
    res.render ("login");
});

app.get("/register",(req,res)=>{
    res.render("register");
});

app.post("/login",async(req,res)=>{
    const {email,password} = req.body;
    let user = await User.findOne({email});
    if(!user) return res.redirect("/register");

    const ismatch = await bcrypt.compare(password,user.password);

    if(!ismatch) return res.render("login",{email,message:"Incorrect password"});

    const token = jwt.sign({ _id: user._id },"eufwfiwegfuwe");

    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    });
    res.redirect("/");

})

app.post("/register",async (req,res)=>{
    const {name,email,password} = req.body;

    let user = await User.findOne({email});
    if(user){
        return res.redirect("/login");
    }

    const hashpwd = await bcrypt.hash(password,10);
     user = await User.create({
        name,
        email,
        password:hashpwd,
    });

    const token = jwt.sign({ _id: user._id },"eufwfiwegfuwe");

    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    });
    res.redirect("/");
});

app.get("/logout",(req,res)=>{
    res.cookie("token","null",{
        httpOnly:true,
        expires: new Date(Date.now()),
    });
    res.redirect("/");
});


app.listen(5000,()=>{
    console.log("server is working");
});
