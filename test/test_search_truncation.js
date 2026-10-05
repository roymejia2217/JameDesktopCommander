// Test script to verify search result behavior using new streaming API
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), 'dc-search-size-home-'));
process.env.HOME = isolatedHome;
process.env.USERPROFILE = isolatedHome;

const { handleStartSearch, handleGetMoreSearchResults, handleStopSearch } =
  await import('../dist/handlers/search-handlers.js');

/**
 * Helper function to wait for search completion and get all results
 */
async function searchAndWaitForCompletion(searchArgs, timeout = 30000) {
  const result = await handleStartSearch(searchArgs);
  if (result.isError === true) {
    throw new Error(`Search failed to start: ${result.content[0].text}`);
  }
  
  // Extract session ID from result with tighter regex
  const sessionIdMatch = result.content[0].text.match(/Started .* session:\s*([a-zA-Z0-9_-]+)/);
  if (!sessionIdMatch) {
    throw new Error('Could not extract session ID from search result');
  }
  const sessionId = sessionIdMatch[1];
  
  try {
    // Wait for completion by polling
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      const moreResults = await handleGetMoreSearchResults({ sessionId });
      
      if (moreResults.content[0].text.includes('✅ Search completed')) {
        return { initialResult: result, finalResult: moreResults, sessionId };
      }
      
      if (moreResults.isError === true) {
        throw new Error(`Search failed: ${moreResults.content[0].text}`);
      }
      
      // Wait a bit before polling again
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    throw new Error('Search timed out');
  } finally {
    // Always stop the search session to prevent hanging
    try {
      await handleStopSearch({ sessionId });
    } catch (e) {
      // Ignore errors when stopping - session might already be completed
    }
  }
}

async function testSearchTruncation() {
    try {
        console.log('Testing search result behavior with new streaming API...');
        
        // Test search that will produce many results
        const searchArgs = {
            path: '.',
            pattern: 'function|const|let|var',  // This should match many lines
            searchType: 'content',
            maxResults: 50000,  // Very high limit to get lots of results
            ignoreCase: true
        };
        
        console.log('Searching for common JavaScript patterns...');
        const { initialResult, finalResult } = await searchAndWaitForCompletion(searchArgs);
        
        console.log('Initial result type:', typeof initialResult.content[0].text);
        console.log('Initial result length:', initialResult.content[0].text.length);
        console.log('Final result type:', typeof finalResult.content[0].text);
        console.log('Final result length:', finalResult.content[0].text.length);
        
        const combinedLength = initialResult.content[0].text.length + finalResult.content[0].text.length;
        
        // Use consistent API limit constant
        const apiLimit = 1048576; // 1 MiB
        if (combinedLength > apiLimit) {
            console.log('⚠️  Combined results quite large - may need truncation handling');
        } else if (finalResult.content[0].text.includes('Results truncated')) {
            console.log('✅ Results properly truncated with warning message');
            const truncationIndex = finalResult.content[0].text.indexOf('Results truncated');
            console.log('Truncation message:', finalResult.content[0].text.substring(truncationIndex, truncationIndex + 100));
        } else {
            console.log('✅ Results manageable size, no truncation needed');
        }
        
        console.log('First 200 characters of final result:');
        console.log(finalResult.content[0].text.substring(0, 200));
        
        // Character length analysis
        console.log(`\n📊 Response Analysis:`);
        console.log(`   Initial response: ${initialResult.content[0].text.length.toLocaleString()} characters`);
        console.log(`   Final response: ${finalResult.content[0].text.length.toLocaleString()} characters`);
        console.log(`   Combined: ${combinedLength.toLocaleString()} characters`);
        
    } catch (error) {
        console.error('Test failed:', error);
        throw error;
    } finally {
        if (originalHome === undefined) delete process.env.HOME;
        else process.env.HOME = originalHome;

        if (originalUserProfile === undefined) delete process.env.USERPROFILE;
        else process.env.USERPROFILE = originalUserProfile;

        await fs.rm(isolatedHome, { recursive: true, force: true });
    }
}

testSearchTruncation().then(() => {
    console.log('Search truncation test completed successfully.');
    process.exit(0);
}).catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
});
