import { AuthenticationService, TokenPayload } from "../authentication.service";
import { Router } from "@angular/router";
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ToastrService }   from 'ngx-toastr';

@Component({
  templateUrl: "./register.component.html"
})
export class RegisterComponent implements OnInit {

  credentials: TokenPayload = {
    password: "",
    id: 0,
    first_name: "",
    last_name: "",
    email: "",
  };

  constructor(private auth: AuthenticationService, private router: Router, private toastr: ToastrService) {}
  model:any = {}
  ngOnInit() {
  }

  register() {
    this.toastr.success('You are Successfully Registered!');

    this.auth.register(this.credentials).subscribe(
      () => {
        this.router.navigateByUrl("/profile");
      },
      err => {
        console.error(err);
      }
    );
  }
}

//}
