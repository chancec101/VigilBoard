// Home.tsx
import React from 'react';

interface HomeProps {
  onLoginSuccess: () => void;
}

const Home: React.FC<HomeProps> = ({ onLoginSuccess }) => {
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    // Access form data
    const username = (e.target as any).username.value;
    const password = (e.target as any).password.value;

    // Perform actions (e.g., send a request to the server)
    try {
      const response = await fetch('http://localhost:5000/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      // Check if the request was successful
      if (response.ok) {
        // Perform actions upon successful login
        console.log('Login successful!');
        // Call the onLoginSuccess callback passed as a prop
        onLoginSuccess();
      } else {
        // Handle login failure (e.g., display an error message)
        console.error('Login failed:', response.statusText);
      }
    } catch (error) {
      console.error('An error occurred during login:', error);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', backgroundColor: '#3498db', color: 'white' }}>
      <h1>VigilBoard Signin</h1>
      <form onSubmit={handleSubmit} style={{ width: '300px' }}>
        <label htmlFor="username">Username:</label>
        <input type="text" id="username" name="username" style={{ marginBottom: '10px' }} />
        <label htmlFor="password">Password:</label>
        <input type="password" id="password" name="password" style={{ marginBottom: '10px' }} />
        <input type="submit" value="Submit" style={{ backgroundColor: '#2980b9', color: 'white', padding: '10px', cursor: 'pointer' }} />
      </form>
    </div>
  );
};

export default Home;
