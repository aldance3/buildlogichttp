export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    const jsonResponse = (value, status = 200) => {
      return new Response(JSON.stringify({ value: value.trim() }), {
        status: status,
        headers: { 'Content-Type': 'application/json' }
      });
    };

    const unauthorizedResponse = (msg = '401 Unauthorized') => {
      return new Response(JSON.stringify({ error: msg }), { 
        status: 401, 
        headers: { 'Content-Type': 'application/json' } 
      });
    };

    try {
      let customGet = null;
      let customPost = null;
      let crossServerCard = null;
      let writeCard = null;
      let writeCustomPost = null;
      let writeDelete = false;
      
      let providedUser = null;
      let providedPass = null;

      const configHeader = request.headers.get('config') || '';
      const writeHeader = request.headers.get('writeconfig') || '';
      
      // 1. IF USING STANDARD CONFIG HEADER
      if (configHeader.trim()) {
        const parts = configHeader.split(';').map(p => p.trim()).filter(Boolean);
        const credsChunk = parts[0];
        
        if (credsChunk && credsChunk.includes('.')) {
          const [user, pass] = credsChunk.split('.').map(item => item.trim());
          providedUser = user;
          providedPass = pass;
        }

        parts.slice(1).forEach(pair => {
          if (pair.includes('=')) {
            const idx = pair.indexOf('=');
            const keyName = pair.substring(0, idx).trim().toLowerCase();
            const valValue = pair.substring(idx + 1).trim();
            if (keyName === 'customget') customGet = valValue;
            if (keyName === 'custompost') customPost = valValue;
            if (keyName === 'server') crossServerCard = valValue;
          }
        });
      }
      
      // 2. IF USING STANDALONE WRITECONFIG HEADER (Extracts credentials from the front)
      else if (writeHeader.trim()) {
        const parts = writeHeader.split(';').map(p => p.trim()).filter(Boolean);
        const credsChunk = parts[0];
        
        if (credsChunk && credsChunk.includes('.')) {
          const [user, pass] = credsChunk.split('.').map(item => item.trim());
          providedUser = user;
          providedPass = pass;
        }

        parts.slice(1).forEach(pair => {
          if (pair.includes('=')) {
            const idx = pair.indexOf('=');
            const keyName = pair.substring(0, idx).trim().toLowerCase();
            const valValue = pair.substring(idx + 1).trim();
            if (keyName === 'card') writeCard = valValue;
            if (keyName === 'custompost') writeCustomPost = valValue;
            if (keyName === 'delete') writeDelete = valValue.toLowerCase() === 'true';
            if (keyName === 'server') { writeCard = valValue; writeCustomPost = 'Server'; }
          }
        });
      }

      // Check if credentials were successfully found in whichever header was sent
      if (!providedUser || !providedPass) {
        return unauthorizedResponse('401 Unauthorized: Missing credentials. Expected "username.password" at the start of your config header.');
      }

      // Fetch all Trello lists
      const listsUrl = `https://api.trello.com/1/boards/${env.TRELLO_BOARD_ID}/lists?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
      const listsResponse = await fetch(listsUrl);
      if (!listsResponse.ok) return jsonResponse('Error: Failed to fetch Trello lists', 500);
      const lists = await listsResponse.json();

      const authList = lists.find(l => l.name.trim().toLowerCase() === 'authorization');
      if (!authList) return jsonResponse('Error: Authorization list missing on board', 500);

      // Fetch list cards
      const authCardsUrl = `https://api.trello.com/1/lists/${authList.id}/cards?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
      const authCardsResponse = await fetch(authCardsUrl);
      const authCards = await authCardsResponse.json();

      const userCard = authCards.find(c => c.name.trim().toLowerCase() === providedUser.toLowerCase());
      if (!userCard) {
        return unauthorizedResponse(`401 Unauthorized: User "${providedUser}" matching card target not found.`);
      }

      // Parse account attributes safely from Trello card description
      const permParts = userCard.desc.split(',');
      const realPassword = permParts[0]?.trim();
      
      let readPermValue = 'true'; 
      let writePermValue = 'false'; 
      let isAdmin = false;

      permParts.forEach(part => {
        if (part.includes('=')) {
          const idx = part.indexOf('=');
          const key = part.substring(0, idx).trim().toLowerCase();
          const val = part.substring(idx + 1).trim().toLowerCase();
          if (key === 'read') readPermValue = val;
          if (key === 'write') writePermValue = val; 
          if (key === 'admin') isAdmin = val === 'true';
        }
      });

      // Password comparison check
      if (providedPass !== realPassword) {
        return unauthorizedResponse('401 Unauthorized: Password mismatch anomaly detected.');
      }

      const hasPermissionForList = (permSetting, listName) => {
        if (permSetting === 'true') return true;
        if (permSetting === 'false') return false;
        const allowedLists = permSetting.split('.').map(item => item.trim().toLowerCase());
        if (allowedLists.includes(listName.toLowerCase())) return true;
        // "post" is shorthand for granting access to the default POSTLIST
        if (listName.toLowerCase() === 'postlist' && allowedLists.includes('post')) return true;
        return false;
      };

      // --- WRITECONFIG INTERCEPT MODE ---
      if (request.headers.has('writeconfig')) {
        const contentType = request.headers.get('content-type') || '';

        // When delete=true, any posted value is ignored entirely (clients that
        // can't send an empty body may send a placeholder like "00000000").
        let postedValue = null;
        if (contentType.includes('application/x-www-form-urlencoded')) {
          const formData = await request.formData();
          postedValue = formData.get('value');
        }

        if (!writeDelete) {
          if (!contentType.includes('application/x-www-form-urlencoded')) {
            return jsonResponse('Error: Expected application/x-www-form-urlencoded for POST body', 400);
          }
          if (!postedValue || postedValue.length !== 8) {
            return jsonResponse('Error: Invalid or missing 8-bit body value parameter', 400);
          }
        }

        if (!writeCard) return jsonResponse('Error: writeconfig header requires card= parameter', 400);

        const targetListName = writeCustomPost || 'POSTLIST';

        if (targetListName.toLowerCase() === 'authorization') {
          return jsonResponse('Error: Modifying authorization list via writeconfig is completely forbidden', 403);
        }
        if (!isAdmin && (targetListName.toLowerCase() === 'getlist' || targetListName.toLowerCase() === 'postlist')) {
          return jsonResponse('Error: Only admins can write to core default lists', 403);
        }
        if (!isAdmin && !hasPermissionForList(writePermValue, targetListName)) {
          return jsonResponse(`Error: Account does not have write permissions for list "${targetListName}"`, 403);
        }

        const targetList = lists.find(l => l.name.trim().toLowerCase() === targetListName.trim().toLowerCase());
        if (!targetList) return jsonResponse(`Error: Target list "${targetListName}" not found`, 404);

        const cardsUrl = `https://api.trello.com/1/lists/${targetList.id}/cards?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
        const cardsResponse = await fetch(cardsUrl);
        const cards = await cardsResponse.json();

        const existingCard = cards.find(c => c.name.trim() === writeCard);

        // --- DELETE PATH ---
        if (writeDelete) {
          if (!existingCard) return jsonResponse(`Error: Card "${writeCard}" not found`, 404);

          const deleteUrl = `https://api.trello.com/1/cards/${existingCard.id}?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
          const deleteResponse = await fetch(deleteUrl, { method: 'DELETE' });
          if (!deleteResponse.ok) return jsonResponse('Error: Failed to delete card', 500);
          return jsonResponse(`Deleted card "${writeCard}"`);
        }

        // --- WRITE (CREATE/UPDATE) PATH ---
        if (existingCard) {
          const updateUrl = `https://api.trello.com/1/cards/${existingCard.id}?desc=${encodeURIComponent(postedValue)}&key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
          const updateResponse = await fetch(updateUrl, { method: 'PUT' });
          if (!updateResponse.ok) return jsonResponse('Error: Failed to update card', 500);
          return jsonResponse(postedValue);
        } else {
          const createUrl = `https://api.trello.com/1/cards?idList=${targetList.id}&name=${encodeURIComponent(writeCard)}&desc=${encodeURIComponent(postedValue)}&key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
          const createResponse = await fetch(createUrl, { method: 'POST' });
          if (!createResponse.ok) return jsonResponse('Error: Failed to create card', 500);
          return jsonResponse(postedValue);
        }
      }

      // --- STANDARD ROUTE MODES (GET/POST) ---
      if (method === 'GET') {
        // --- CROSS-SERVER MODE: config header included Server=CardName ---
        if (crossServerCard) {
          const targetListName = 'Server';
          if (!hasPermissionForList(readPermValue, targetListName)) {
            return jsonResponse(`Error: Read permission denied for list "${targetListName}"`, 403);
          }

          const serverList = lists.find(l => l.name.trim().toLowerCase() === targetListName.toLowerCase());
          if (!serverList) return jsonResponse('Error: Server list not found', 500);

          const cardsUrl = `https://api.trello.com/1/lists/${serverList.id}/cards?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
          const cardsResponse = await fetch(cardsUrl);
          const cards = await cardsResponse.json();

          const serverCard = cards.find(c => c.name.trim().toLowerCase() === crossServerCard.trim().toLowerCase());
          if (!serverCard) return jsonResponse(`Error: Card "${crossServerCard}" not found`, 404);

          return jsonResponse(serverCard.desc);
        }

        const targetListName = 'GETLIST';
        const getList = lists.find(l => l.name === targetListName);
        if (!getList) return jsonResponse('Error: GETLIST not found', 500);

        const targetCardName = customGet || 'Get';

        // Permission is now checked against the specific card being requested
        // inside GETLIST, not against the list itself. readPermValue can be
        // true/false, or a dot-separated allowlist of card names.
        if (!hasPermissionForList(readPermValue, targetCardName)) {
          return jsonResponse(`Error: Read permission denied for card "${targetCardName}"`, 403);
        }

        const cardsUrl = `https://api.trello.com/1/lists/${getList.id}/cards?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
        const cardsResponse = await fetch(cardsUrl);
        const cards = await cardsResponse.json();

        const getCard = cards.find(c => c.name.trim().toLowerCase() === targetCardName.trim().toLowerCase());
        if (!getCard) return jsonResponse(`Error: Card "${targetCardName}" not found`, 404);

        return jsonResponse(getCard.desc);
      }

      if (method === 'POST') {
        const contentType = request.headers.get('content-type') || '';
        if (!contentType.includes('application/x-www-form-urlencoded')) {
          return jsonResponse('Error: Expected application/x-www-form-urlencoded', 400);
        }

        const formData = await request.formData();
        const postedValue = formData.get('value');

        if (!postedValue || postedValue.length !== 8) return jsonResponse('Error: Invalid 8-bit parameter', 400);

        // --- CROSS-SERVER MODE: config header included Server=CardName ---
        // POST here WRITES the posted value as the card's new description,
        // unlike the standard POST path below which only reads/looks up a card.
        if (crossServerCard) {
          const targetListName = 'Server';
          if (!isAdmin && !hasPermissionForList(writePermValue, targetListName)) {
            return jsonResponse(`Error: Account does not have write permissions for list "${targetListName}"`, 403);
          }

          const serverList = lists.find(l => l.name.trim().toLowerCase() === targetListName.toLowerCase());
          if (!serverList) return jsonResponse('Error: Server list not found', 500);

          const cardsUrl = `https://api.trello.com/1/lists/${serverList.id}/cards?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
          const cardsResponse = await fetch(cardsUrl);
          const cards = await cardsResponse.json();

          const serverCard = cards.find(c => c.name.trim().toLowerCase() === crossServerCard.trim().toLowerCase());

          if (serverCard) {
            const updateUrl = `https://api.trello.com/1/cards/${serverCard.id}?desc=${encodeURIComponent(postedValue)}&key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
            const updateResponse = await fetch(updateUrl, { method: 'PUT' });
            if (!updateResponse.ok) return jsonResponse('Error: Failed to update card', 500);
            return jsonResponse(postedValue);
          } else {
            const createUrl = `https://api.trello.com/1/cards?idList=${serverList.id}&name=${encodeURIComponent(crossServerCard)}&desc=${encodeURIComponent(postedValue)}&key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
            const createResponse = await fetch(createUrl, { method: 'POST' });
            if (!createResponse.ok) return jsonResponse('Error: Failed to create card', 500);
            return jsonResponse(postedValue);
          }
        }

        const targetListName = customPost || 'POSTLIST';

        if (targetListName.toLowerCase() === 'authorization') {
          return jsonResponse('Error: Reading the authorization list is completely forbidden', 403);
        }

        if (!hasPermissionForList(readPermValue, targetListName)) {
          return jsonResponse(`Error: Read permission denied for list "${targetListName}"`, 403);
        }

        const targetList = lists.find(l => l.name.trim().toLowerCase() === targetListName.trim().toLowerCase());
        if (!targetList) return jsonResponse(`Error: List "${targetListName}" not found`, 404);

        const cardsUrl = `https://api.trello.com/1/lists/${targetList.id}/cards?key=${env.TRELLO_KEY}&token=${env.TRELLO_TOKEN}`;
        const cardsResponse = await fetch(cardsUrl);
        const cards = await cardsResponse.json();

        const targetCard = cards.find(c => c.name.trim() === postedValue.trim());
        if (!targetCard) return jsonResponse(`Error: Card "${postedValue}" not found`, 404);

        return jsonResponse(targetCard.desc);
      }

      return jsonResponse('Error: Method not allowed', 405);

    } catch (error) {
      return jsonResponse(`Error: ${error.message}`, 500);
    }
  }
};
