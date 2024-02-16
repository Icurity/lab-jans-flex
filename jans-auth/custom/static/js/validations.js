function validateEmail(email) {
  const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return emailRegex.test(email);
}

function validateMsisdn(msisdn) {
  return /^(0|27)((?=\d*$)(?:.{9}|.{13}))$/g.test(msisdn);
}

function isNigMobileNumber(phoneNo) {
  const startStringsArrays = ['07', '08', '09'];
  const standardLengthOfMobile = 11;
  const pattern = /^[0-9]*$/;
  if(!pattern.test(phoneNo)) {
    return false;
  }
  if(standardLengthOfMobile !== phoneNo.length) {
    return false;
  }
  
  let startPart = phoneNo.substring(0, 2);
  if(!startStringsArrays.includes(startPart)) {
    return false;
  }

  return true;
}

function validatePassword(password) {
  return /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/.test(password);
}

function validate(obj) {
  var val = document.getElementById("loginForm:username").value;
  var regex = /^[0-9\.]+$/;

  if (regex.test(val)) {
    if (isBvnValid(val)) {
      document.getElementById("loginButton_b").style.display = "block";
      obj.style.display = "none";
      if(document.getElementById('custom-loader') !== null){
      	document.getElementById('custom-loader').style.display = 'flex';
      }
      return true;
    }
    else {
      document.getElementById("loginForm:username").style.borderColor = "red";
      document.getElementById("loginForm:err").innerHTML = '<span style="color:red;">Enter a valid BVN number.</span>';
      return false;
    }

  }
  else {
    document.getElementById("loginForm:username").style.borderColor = "red";
    return false;
  }
}

function isBvnValid(bvn) {
  //constants
  const ArrayOfBVNMAGICNUMBERS = [3, 1, 7, 3, 1, 7, 3, 1, 7, 3];
  const STANDARDLENGTHOFBVN = 11;
  const pattern = /^[0-9]*$/;
  if (!pattern.test(bvn)){
    return false;
  }
    

  //set args here
  let bvnSpan = bvn;
  if (STANDARDLENGTHOFBVN !== bvnSpan.length) {
    return false;
  }

  let sumofBVNWeight = 0;
  for (let positionHolder = 0; positionHolder < ArrayOfBVNMAGICNUMBERS.length; positionHolder++) {
    let BVNWeight = ArrayOfBVNMAGICNUMBERS[positionHolder];

    let bvnSlice = bvnSpan.slice(positionHolder, positionHolder + 1);
    sumofBVNWeight = sumofBVNWeight + (BVNWeight * bvnSlice);
  }
  let ModulusOfWeight = sumofBVNWeight % 10;
  let lastDigitBVN = bvnSpan.slice(10);
  if (lastDigitBVN == ModulusOfWeight) {
    return true;
  }
  else {
    return false;
  }
}
