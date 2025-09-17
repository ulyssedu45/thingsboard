///
/// Copyright © 2016-2025 The Thingsboard Authors
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.
///

import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { AuthService } from '@core/auth/auth.service';
import { Store } from '@ngrx/store';
import { AppState } from '@core/core.state';
import { PageComponent } from '@shared/components/page.component';
import { UntypedFormBuilder, Validators } from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
  selector: 'tb-kerberos-login',
  templateUrl: './kerberos-login.component.html',
  styleUrls: ['./kerberos-login.component.scss']
})
export class KerberosLoginComponent extends PageComponent implements OnInit {

  @Output() kerberosLoginSuccess = new EventEmitter<void>();

  kerberosFormGroup = this.fb.group({
    username: ['', [Validators.required, Validators.email]],
    kerberosToken: ['', Validators.required]
  });

  kerberosEnabled = false;

  constructor(protected store: Store<AppState>,
              private authService: AuthService,
              public fb: UntypedFormBuilder,
              private snackBar: MatSnackBar) {
    super(store);
  }

  ngOnInit() {
    this.checkKerberosStatus();
  }

  checkKerberosStatus(): void {
    this.authService.checkKerberosStatus().subscribe(
      (response) => {
        this.kerberosEnabled = response.enabled;
      },
      (error) => {
        console.warn('Kerberos authentication not available', error);
        this.kerberosEnabled = false;
      }
    );
  }

  kerberosLogin(): void {
    if (this.kerberosFormGroup.valid) {
      const kerberosRequest = this.kerberosFormGroup.value;
      this.authService.kerberosLogin(kerberosRequest).subscribe(
        () => {
          this.kerberosLoginSuccess.emit();
        },
        (error: HttpErrorResponse) => {
          let errorMessage = 'Kerberos authentication failed';
          if (error?.error?.message) {
            errorMessage = error.error.message;
          }
          this.snackBar.open(errorMessage, 'Close', {
            duration: 5000,
            panelClass: 'tb-error'
          });
        }
      );
    } else {
      Object.keys(this.kerberosFormGroup.controls).forEach(field => {
        const control = this.kerberosFormGroup.get(field);
        control.markAsTouched({onlySelf: true});
      });
    }
  }

  spnegoLogin(): void {
    this.authService.kerberosSpnegoLogin().subscribe(
      () => {
        this.kerberosLoginSuccess.emit();
      },
      (error: HttpErrorResponse) => {
        let errorMessage = 'SPNEGO authentication failed. Make sure your browser is configured for Kerberos authentication.';
        if (error?.error?.message) {
          errorMessage = error.error.message;
        }
        this.snackBar.open(errorMessage, 'Close', {
          duration: 7000,
          panelClass: 'tb-error'
        });
      }
    );
  }
}