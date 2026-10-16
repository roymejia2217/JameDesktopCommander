import assert from 'node:assert/strict';
import { test } from 'node:test';
import { executeTunnelProbe } from '../dist/tools/tunnel-probe.js';
import {
  verifyMcpRoundTripResponse,
  verifyMcpRoundTripPair,
} from '../dist/tools/tunnel-probe-verification.js';

const COMMIT = 'a'.repeat(40);
const VERSION = '0.2.52';
const FIRST = '0123456789abcdef0123456789abcdef';
const SECOND = 'fedcba9876543210fedcba9876543210';
const now = Date.parse('2026-10-16T12:00:00.000Z');
const gitBuild = {schemaVersion:1,kind:'git',sourceCommit:COMMIT,
  packageVersion:VERSION,workspaceClean:true};
const clock = () => new Date(now);
const request = (challenge=FIRST, start=now-80, end=now+100) => ({
  challenge,expectedCommit:COMMIT,expectedPackageVersion:VERSION,
  requestStartedAtMs:start,responseReceivedAtMs:end,
});
const makeResponse = (challenge=FIRST, build=gitBuild) =>
  executeTunnelProbe({challenge},async()=>build,clock);

function alter(resp, modify) {
  const copy = structuredClone(resp);
  modify(copy.structuredContent);
  copy.content[0].text = JSON.stringify(copy.structuredContent);
  return copy;
}
const hold = (reason, got) => assert.deepEqual(got,{kind:'hold',reason});

test('genuine server response is verified using the request nonce and pinned build identity',async()=>{
  const response=await makeResponse();
  const got=verifyMcpRoundTripResponse(request(),response);
  assert.equal(got.kind,'verified');
  assert.equal(got.sourceCommit,COMMIT);
  assert.equal(got.packageVersion,VERSION);
  assert.equal(got.runtimeInstanceId,response.structuredContent.runtimeInstanceId);
  assert.ok(!('restartAllowed' in got));
});

test('two distinct real challenge calls require the same process instance',async()=>{
  const a=await makeResponse(FIRST),b=await makeResponse(SECOND);
  const got=verifyMcpRoundTripPair(request(FIRST),a,request(SECOND),b);
  assert.equal(got.kind,'verified');
  hold('duplicate_challenge',verifyMcpRoundTripPair(request(FIRST),a,request(FIRST),a));
  const changed=alter(b,x=>{x.runtimeInstanceId='00000000-0000-4000-8000-000000000001'});
  hold('instance_changed',verifyMcpRoundTripPair(request(FIRST),a,request(SECOND),changed));
});

test('wrong nonce cannot be mistaken for a fresh request even when JSON matches',async()=>{
  const response=await makeResponse(SECOND);
  hold('challenge_mismatch',verifyMcpRoundTripResponse(request(FIRST),response));
  hold('challenge_mismatch',verifyMcpRoundTripResponse(request(SECOND),await makeResponse(FIRST)));
});

test('exact schemas refuse injected fields, malformed IDs and divergent content',async()=>{
  const clean=await makeResponse();
  const cases=[
    alter(clean,x=>{x.secret='Bearer sentinel'}),
    alter(clean,x=>{x.schemaVersion=2}),
    alter(clean,x=>{x.kind='ready'}),
    alter(clean,x=>{x.runtimeInstanceId='not-a-uuid'}),
    alter(clean,x=>{x.runtimeInstanceId='00000000-0000-1000-8000-000000000000'}),
    {...clean,content:[]},
    {...clean,content:[...clean.content, ...clean.content]},
    {...clean,content:[{type:'text',text:'not json'}]},
    {...clean,content:[{type:'text',text:'x'.repeat(2049)}]},
    {...clean,isError:true},
    {content:clean.content},
    {...clean,structuredContent:undefined},
    {...clean,content:[{type:'text',text:JSON.stringify({...clean.structuredContent,challenge:SECOND})}]},
    null,
  ];
  for(const candidate of cases){
    hold('invalid_response',verifyMcpRoundTripResponse(request(),candidate));
  }
});

test('invalid caller inputs cannot turn errors into a valid observation',async()=>{
  const response=await makeResponse();
  for(const invalid of [
    {...request(),challenge:FIRST.toUpperCase()},
    {...request(),challenge:'f'},
    {...request(),expectedCommit:'b'},
    {...request(),expectedCommit:COMMIT.toUpperCase()},
    {...request(),expectedPackageVersion:'nightly'},
    {...request(),requestStartedAtMs:NaN},
    {...request(),responseReceivedAtMs:Infinity},
    {...request(),requestStartedAtMs:now+500},
    {...request(),debugToken:'secret'},
    null,
  ]){
    hold('invalid_request',verifyMcpRoundTripResponse(invalid,response));
  }
});

test('late responses are not certified as live',async()=>{
  const response=await makeResponse();
  hold('late_response',verifyMcpRoundTripResponse(request(FIRST,now,now+30001),response));
  assert.equal(verifyMcpRoundTripResponse(request(FIRST,now-100,now+200),response).kind,'verified');
});

test('server clock must use a canonical UTC timestamp within bounded skew',async()=>{
  const response=await makeResponse();
  for(const date of [
    '2026-10-16T12:00:00Z',
    '2026-02-30T12:00:00.000Z',
    '2026-10-16T12:00:00.000+00:00',
    '2026-10-16T11:57:59.000Z',
    '2026-10-16T12:02:01.000Z',
    'NaN',
  ]){
    const bad=alter(response,x=>{x.observedAtUtc=date});
    hold('untrusted_observation_time',verifyMcpRoundTripResponse(request(),bad));
  }
});

test('unknown, dirty and unexpected build provenance never proves the deployed revision',async()=>{
  const unknown=await makeResponse(FIRST,{schemaVersion:1,kind:'unavailable'});
  hold('unavailable_build',verifyMcpRoundTripResponse(request(),unknown));
  const good=await makeResponse();
  for(const bad of [
    alter(good,x=>{x.runtimeBuild.sourceCommit='b'.repeat(40)}),
    alter(good,x=>{x.runtimeBuild.workspaceClean=false}),
    alter(good,x=>{x.runtimeBuild.packageVersion='0.3.0'}),
  ]){
    hold('unexpected_build',verifyMcpRoundTripResponse(request(),bad));
  }
  const malformed=alter(good,x=>{x.runtimeBuild.extra='leak'});
  hold('invalid_response',verifyMcpRoundTripResponse(request(),malformed));
});

test('verifying a response has no lifecycle or OS side effects',async()=>{
  const r=await makeResponse();
  const before=structuredClone(r);
  const p=request();
  const expected=structuredClone(p);
  assert.equal(verifyMcpRoundTripResponse(p,r).kind,'verified');
  assert.deepEqual(p,expected);
  assert.deepEqual(r,before);
});
