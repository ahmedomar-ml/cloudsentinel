import { provideHttpClient } from '@angular/common/http';
import { bootstrapApplication } from '@angular/platform-browser';
import { DashboardComponent } from './app/dashboard.component';

bootstrapApplication(DashboardComponent, {
  providers: [provideHttpClient()],
}).catch((err) => console.error(err));
