import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthenticationService, TokenPayload } from '../authentication.service'
import { Router } from '@angular/router'
import { ToastrService }   from 'ngx-toastr';

@Component({
  templateUrl: './login.component.html'
})
export class LoginComponent implements OnInit{
  credentials: TokenPayload = {
    id: 0,
    first_name: '',
    last_name: '',
    email: '',
    password: ''
  }

  constructor(private auth: AuthenticationService, private router: Router, private toastr: ToastrService) {}
   model:any = {}
  ngOnInit() {
  }
  login() {


    this.auth.login(this.credentials).subscribe(
      () => {

        this.router.navigateByUrl('/profile')
      },
      err => {
        console.error(err)
      }
    )
  }
}
