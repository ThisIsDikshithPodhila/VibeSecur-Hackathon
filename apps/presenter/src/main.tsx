import React from 'react';
import { createRoot } from 'react-dom/client';
import EmployeeApp from './EmployeeApp';
import './employee-app.css';

createRoot(document.getElementById('root')!).render(<React.StrictMode><EmployeeApp /></React.StrictMode>);
