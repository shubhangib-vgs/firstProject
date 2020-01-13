import { Component } from '@angular/core'
import { AuthenticationService, UserDetails } from '../authentication.service'
import { ToastrService }   from 'ngx-toastr';

@Component({
      templateUrl: './profile.component.html'
})
export class ProfileComponent{
  details : UserDetails

  constructor(private auth: AuthenticationService,private toastr: ToastrService){}

  ngOnInit(){
      this.toastr.success('You are Successfully Logged In!');
      this.details= this.auth.getUserDetails()
  }
}
