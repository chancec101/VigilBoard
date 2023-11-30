// App.tsx
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from './Home';
import Login from './Login';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
  };

  return (
    <Router>
      <div className="App" style={{ textAlign: 'center', backgroundColor: '#3498db', color: 'white', height: '100vh' }}>
        <header className="App-header">
          <h1>VigilBoard Homepage</h1>
          {isLoggedIn ? (
            <p>Welcome! You are now logged in.</p>
          ) : (
            <Routes>
              {/* Pass the handleLoginSuccess function as a prop */}
              <Route path="/login" element={<Login onLoginSuccess={handleLoginSuccess} />} />
              <Route path="/" element={<Home onLoginSuccess={handleLoginSuccess} />} />
            </Routes>
          )}
        </header>
      </div>
    </Router>
  );
}

export default App;
