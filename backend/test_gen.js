const axios = require('axios');

async function test() {
  try {
    const res = await axios.post('http://127.0.0.1:11434/api/generate', {
      model: 'llama3',
      prompt: 'Respond with "pong".',
      stream: false
    });
    console.log('Success:', res.data.response);
  } catch (err) {
    console.error('Error:', err.message);
    if (err.response) {
      console.error('Response data:', err.response.data);
    }
  }
}

test();
