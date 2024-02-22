const express = require("express");
const port = process.env.PORT || 3000;
const mysql = require("mysql");
const dotenv = require("dotenv");
const path = require('path');
const hbs = require('hbs');
const cookieParser = require("cookie-parser");

dotenv.config({path:'./.env'});
const app = express();

const db = mysql.createConnection({
    host:process.env.host,
    user:process.env.user,
    password:process.env.pass,
    database:process.env.DATABASE
});



app.use(cookieParser());

const publicDirectory = path.join(__dirname, './public');
app.use(express.static(publicDirectory));

const partialsPath = path.join(__dirname, './views/partials');
hbs.registerPartials(partialsPath);
app.set('view engine', 'hbs');

db.connect((error)=>{
    if(error){
        console.log(error)
    }else{
        console.log("Connected to database....");
    }
})
app.use(express.urlencoded({ extended: true }));


app.use('/', require("./routes/pages"));
app.use('/auth', require("./routes/auth"));

app.listen(port, () => {
  console.log(`Server Stared on port ${port}`)
})