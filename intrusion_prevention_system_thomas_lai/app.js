var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
//var project = require('./bin/www');
var index = require('./routes/index.js');
var users = require('./routes/users');

var app = express();


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', index);
app.use('/users', users);

//const index1 = require('./routes/index');

//index.changeEX("HELP");
//
//send to index.html
//app.get('/',function(req,res){
//res.sendFile('index.html');
//});

/// TESTING CODE HERE
//exports.iptables = function(req,res,next){
//res.render('iptables');
//};

//END TESTING


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});


app.get('/iptables', function(req,res){
res.render('iptables',{});
});


const fs = require('fs');
const{exec}=require('child_process');
var fn = [];//"access.log"];//,"auth.log"];
var laststring = [];
var sshstring;
var lastsshstring;
var ipbanlog=[];
var max_counter = 3;
var timeout = 5;
var watchSSH = 0;
var sshwatcher;
var sshint;
var child=null;


function Suspects(ip, count){
  this.ip = ip;
  this.count = count;
}

var watchlist = [];



function loadConfig(){
  console.log("Phase 1");
  parseConfig();
  console.log("Phase 2");
  checkSituation();
  console.log("Phase 3");
  toggleSSHAuthLog(watchSSH);
}



function toggleSSHAuthLog(factor){
  if(factor == 1){
    if(typeof(sshwatcher) != 'undefined')
      try{sshwatcher.close();}catch(err){console.log("Unable to close auth.log watch\n"+err);}
  }else{
    checkSituationSSH();
    watchSSHLogs();
  }
}

function deliverBanQueue(){

  child=exec('for j in $(sudo atq | sudo sort -k6,6 -k3,3M -k4,4 -k5,5 | sudo cut -f 1); do sudo atq |grep -P "^$j\t" ;sudo at -c "$j" | tail -n 2; done', (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.log(`stderr: ${stderr}`);
  });
}
function parseConfig(){
//Run through the files and log the last lines for comparisons later on
  var data = fs.readFileSync(('/superjs.conf'));
  if(data !=null){
    var splitter = (data.toString('ascii')).split('\n');
    for(var index = 0; index < splitter.length; index++){
      var finder = splitter[index].split('=');
      if((finder[0].trim()) == 'timeout'){
        console.log("timeout: "+ parseInt(finder[1].trim()));
        try{timeout = parseInt(finder[1].trim());}catch(err){console.log("Problem trying to parse timeout variable in super.js.conf.\n"+ err);}
      }
      else if((finder[0].trim()) == 'max_counter'){
	       console.log("max_counter: "+ parseInt(finder[1].trim()));
        try{max_counter = parseInt(finder[1].trim());}catch(err){console.log("Problem trying to parse max_counter variable in super.js.conf.\n"+ err);}
	       }
      else if((finder[0].trim()) == 'Secure SSH Connection(0 for yes, 1 for no)'){
        console.log("Secure SSH Connection: "+ parseInt(finder[1].trim()));
        try{watchSSH = parseInt(finder[1].trim());}catch(err){console.log("Problem trying to parse Secure SSH Connection variable in super.js.conf.\n"+ err);}
      }
      else if((finder[0].trim()) == 'filenames'){
        var filenames = finder[1].split(',');
        var fns = [];
        for(var fnsi = 0; fnsi < filenames.length; fnsi++)
          try{fns.push(filenames[fnsi].trim());}catch(err){console.log("Problem trying to parse filenames in super.js.conf.\n"+ err);}
	           fn= fns;
      }
    }
	console.log(max_counter);
	console.log(timeout);
	  for(var r = 0; r < fns.length; r++){
	     console.log("File names:"+ fns[r]);
    }
  }
  else
    console.log("Config file is empty, using defaults: \ntimeout = 5 minutes\nmax_counter = 3\nSecure SSH Connection=0");
}


function addToWatchlist(ipaddr){
  watchlist.push(new Suspects(ipaddr, 1));
  console.log("WATCHLIST CHANGES: =========\t"+watchlist[watchlist.length-1].ip+"\t"+ watchlist[watchlist.length-1].count + "  ===============");
}

function ban(ind){
console.log(timeout);
console.log(max_counter);
 child=exec('cd;sudo iptables -A INPUT -s '+ watchlist[ind].ip+' -j DROP;echo \"sudo iptables -D INPUT -s '+watchlist[ind].ip+' -j DROP\" | sudo at now+'+timeout+'minute;', (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.log(`stderr: ${stderr}`);
  });
  ipbanlog.push(watchlist[ind].ip);
  console.log("IP BANNED: "+watchlist[ind].ip + " for "+ timeout + " minutes");
  watchlist[ind].ip = -1;
  watchlist[ind].count = 0;
 // deliverBanQueue();
}

function checkSituation(){
  laststring = [];
  for(var i = 0; i<fn.length;i++){
    var data = fs.readFileSync(('/var/log/apache2/'+fn[i]));
    if(data !=null){
      var turn = data.toString('ascii');
      var lastline = turn.split('\n');
      laststring.push(lastline.length-2);
    }
    else
      laststring.push(-1);
  }
}

function checkSituationSSH(){
  var data = fs.readFileSync('/var/log/auth.log');
  if(data !=null){
    var buffr = data.toString('ascii');
    var modified = buffr.split('\n');
    lastsshstring = modified[modified.length-2];
    sshint = modified.length-2;
  }
  else
    sshint =-1;
}

function watchSSHLogs(){
  sshwatcher = fs.watch('/var/log/auth.log',function(event,filename){
    fs.readFile('/var/log/auth.log','ascii',(err,data)=>{
      if(err)throw err;
      if(data != null){
        var infofilter = (data.toString('ascii')).split('\n');
        var sshchecktool = [];
        var sshfound = -1;
        var failed = "Failed password";
        for(var index = sshint+1; index < infofilter.length; index ++){
            sshchecktool.push(infofilter[index]);
            if(infofilter[index].indexOf(failed)!== -1){//////////////////////////////////////////////////Failed password check
		            var infofilter2 = infofilter[index].split(failed);
		            var infofilter1 = infofilter2[1].split("from")
                var splits = infofilter1[1].split(' ');
                var ipssh = splits[1];
                for(var index2 = 0; index2 < watchlist.length;index2++){
                  if(ipssh == watchlist[index2].ip){
                    watchlist[index2].count+=1;
		                console.log("Watch List Update: "+ watchlist[index2].ip + "\t" + watchlist[index2].count);
                    sshfound = 1;
                    if(watchlist[index2].count >= max_counter){
                      ban(index2);
                    }
                  }
                }

                if(sshfound == -1){/////////////////////////////////////////////////no previous record

                  var sshemptyspace = 0;

                  for(var index2 = 0; index2 < watchlist.length; index2++){
                    if(watchlist[index2].ip == -1){
                      sshemptyspace = 1;
                      watchlist[index2].ip = ipssh;
                      watchlist[index2].count = 1;
                      index2 = watchlist.length;
                    }
                  }

                  if(sshemptyspace == 0){
			console.log("Failed Authentication on SSH");
                    addToWatchlist(ipssh);
                  }
                }///////////////////////////////////////////////////////////////////
            }////////////////////////////////////////////////////////////////////////////////////////////
        }
        sshint = infofilter.length-2;
      }
    });
  });
}

loadConfig();
beginWatch();
//listen to log changes
function beginWatch(){
fs.watch('/var/log/apache2/', function(event, filename){
  var x = -1;
  for(var k = 0; k < fn.length; k++){//identify if source of event is same as a registered auth log file
    if(filename == fn[k])
      x = k;
  }
  var checktool=[];

  if(x != -1){//if it is then place any line after latest registered line into checktool
    fs.readFile(('/var/log/apache2/'+fn[x]),'ascii',(err,data) => {//======================================================================================================================
      var tur = (data.toString('ascii')).split('\n');//data split by newline
      for(var j = laststring[x]+1; j < tur.length;j++){
        var cipher=[];
        var post = 0;
	      var checking = 0;

        if(tur[j].indexOf("GET")!=-1){
          var cipher1 = tur[j].split('GET');
          cipher = cipher1[cipher1.length-1].split(' ');
	        var tiplog = cipher1[0].split(' ');
	        cipher[0] = tiplog[0];
        }
        else if(tur[j].indexOf("POST")!=-1){
          post= 1;
          var cipher1 = tur[j].split('POST');
          cipher = cipher1[cipher1.length-1].split(' ');
	        var tiplog = cipher1[0].split(' ');
	        cipher[0] = tiplog[0];
        }
        else {
          checking = 1;
        }
        if(checking != 1){
          if((typeof(cipher) != 'undefined')&&(typeof(cipher[0])!= 'undefined')&&(typeof(cipher[3])!= 'undefined')){
            console.log("\n==Change Detected==");
	           console.log("cipher results: "+cipher[0] + "\t"+cipher[3]);
             for(var gur = 0; gur < cipher.length; gur++){
               console.log("Cipher Line "+ gur+ ":" + cipher[gur]);
             }
	          }

            if(cipher[3] == "200" && (cipher[1] == "/" || cipher[1] == "/wp-admin/")){//////////////////////////////////////Signed in correctly and authenticated////////////////////////////////
              console.log("Authentication Successful.");
              for(var b = 0; b < watchlist.length;b++){
                if(watchlist[b].ip == cipher[0]){
                  watchlist[b].ip = -1;
                  watchlist[b].count = 0;
                }
              }
            }/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	           else if((cipher[3] == "401" && cipher[1] == "/") || ((cipher[1].indexOf("view=login")!=-1)&& post == 0) || (post == 1 && cipher[3] == "200")){
	              console.log("Authentication Invalid.\n");
	               console.log("Watch List: ");
			var trigger=0 ;
                 /////////////////////////////////////////////////////////////////////////////////////Check if record exists in watchlist
                 for(var b = 0; b < watchlist.length;b++){
	                  if(watchlist[b].ip != -1)
	                   console.log("\t"+watchlist[b].ip + "\t" + watchlist[b].count);
                     if(watchlist[b].ip == cipher[0]){//existing record
			console.log("MAX:"+ max_counter );
                       watchlist[b].count += 1;
			trigger = 1;
                       // check if maximum counts reached, if yes then ban
                       if(watchlist[b].count >= max_counter){
                         ban(b);

                }
                     }
                   }
                   //////////////////////////////////////////////////////////////////////No existing record
                   //insert new ip to watchlist
                   var added = 0;
					if(trigger == 0){

                   for(var b = 0; b < watchlist.length;b++){
                     if(watchlist[b].ip == -1){
                       watchlist[b].ip= cipher[0];
                       watchlist[b].count = 1;
			trigger = 1;
	console.log("trigger: "+ trigger);
           console.log("WATCHLIST CHANGES:=========  "+ watchlist[b].ip + "\t" + watchlist[b].count + "  ===============");
                          added = 1;
                          b = watchlist.length+10;
                        }
                      }
			}
                      if(added == 0 && trigger == 0){//no empty space available
			console.log("trigger1:"+trigger);
                        //append new Suspect to watchlist
	                       addToWatchlist(cipher[0]);
                       }
                     }
                   }/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////INVALID AUTH
        //Changes to file are logged and printed out
        checktool.push(tur[j]);
        //console.log("File Changes: " + checktool.toString());

        //update last line
      }
        laststring[x] = tur.length-2;
    });//==============================================================================================================================================================

    //if(filename)
    //console.log('filename provided: ' + filename);
    //else
    //console.log('no filename');
  }
});
}

//app.post('showtable',function(req,res){
//res.sendFile(path.join(__dirname+'showtables.html'));
//for(var i = 0; i < watchlist.length;i++){
//res.set('Content-Type','text/html');
//res.send(new Buffer("<tr>"+watchlist[i]+"<tr>"));
//}
//});

function on_exit(){
console.log('Process Exit');
if(child != null){
child.kill();
}
process.exit(0);
}

process.on('SIGINT', on_exit);
process.on('exit',on_exit);

module.exports = app;
