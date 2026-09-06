import { describe, expect, test } from 'bun:test';
import { conversationMessage } from './investigator';

describe('agent conversation transparency', () => {
  test('separates Ollama reasoning content from the assistant answer', () => {
    const message = conversationMessage({
      _getType: () => 'ai',
      content: 'I will inspect the observed endpoint.',
      additional_kwargs: { reasoning_content: 'The response evidence suggests the endpoint deserves a bounded follow-up.' }
    }, 4, '2026-09-06T20:00:00.000Z');
    expect(message).toMatchObject({
      role: 'assistant',
      content: 'I will inspect the observed endpoint.',
      reasoning: 'The response evidence suggests the endpoint deserves a bounded follow-up.',
      sequence: 4
    });
  });

  test('extracts standardized reasoning blocks without duplicating them in content', () => {
    const message = conversationMessage({ role: 'assistant', content: [
      { type: 'reasoning', reasoning: 'Evaluate the content signature before trusting status.' },
      { type: 'text', text: 'The file response requires validation.' }
    ] }, 1);
    expect(message.reasoning).toBe('Evaluate the content signature before trusting status.');
    expect(message.content).toBe('The file response requires validation.');
  });
});
