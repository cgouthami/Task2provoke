 const {Client} =require('pg')

 const client=new Client({
    host: "localhost",
    user:"postgres",
    port:5432,
    password:"plsql",
    database:"Sample"
 })

 client.connect();

 client.query(`select * from users`, (err, res)=>{
    if(!err){
        console.log(res.rows);
    }
    else{
        console.log(err.message)
    }
    client.end;
 })