const express = require("express");
const app=express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session=require("express-session");
const flash=require("express-flash");
const passport = require("passport");

const initializePassport = require("./passportConfig");

initializePassport(passport);
const PORT=process.env.PORT || 4000;

app.set("view engine","ejs");
app.use(express.urlencoded({ extended: false }));

app.use(
    session({
        secret:"secret",
        resave: false,
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());
app.get("/", (req, res)=>{
    res.render("index");
});

app.get("/users/register", checkAuthenticated, (req,res)=>{
    res.render("register");
});

app.get("/users/login", checkAuthenticated, (req,res)=>{
    res.render("login");
});

app.get("/users/dashboard", checkAuthenticated, (req,res)=>{
    res.render("dashboard",{ user: "User"});
});

app.get("/users/logout", (req, res)=>{
    req.logOut();
    req.flash("success_msg", "You have logged out");
    res.redirect("/users/login");
})
app.post("/users/register", async (req, res)=>{
    let { id, pwd, confirmpwd } = req.body;
    console.log(
        {
            id,
            pwd,
            confirmpwd
        }
    );


let errors = []
    
if(!id || !pwd){
    errors.push({ message: "Please enter all fields" });

}


if(pwd!=confirmpwd){
    errors.push({ message: "Passwords do not match"});

}

if(errors.length > 0){
    res.render("register", { errors });
}
else{

    let hashedPassword = await bcrypt.hash(pwd, 10);
    console.log(hashedPassword);
    pool.query(
        `SELECT * FROM users 
        WHERE id=$1`,[id],
        (err, results) => {
            if(err) {
                throw err;
            }
           
            console.log(results.rows);

            if(results.rows.length > 0){
                errors.push({ message: "id already exist"});
                res.render("register", {errors});
            }
            else{
                pool.query(
                    `INSERT INTO users (id,password)
                    VALUES ($1,$2)
                    RETURNING id,password`,
                    [id,pwd],
                    (err, results)=>{
                        if(err) {
                            throw err;
                        }
                        console.log(results.rows);
                        req.flash("success_msg","You are now registered. Plesae log in");
                        res.redirect("/users/login");
                    }
                )
            }
        }
    );
}
});

app.post("/users/login", passport.authenticate
("local",{
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
}));

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/users/dashboard");
    }
    next();
}

function checkNoAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
}
app.listen(PORT,()=>
{
    console.log(`server running on port ${PORT}`);
})

