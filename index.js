import { pipeline } from '@huggingface/transformers';
import { GlobalPIIDetector } from './global-pii-detector.js';

export class PIIWarden {
  constructor(config = {}) {
    this.detector = new GlobalPIIDetector(config);
    this.nerPipeline = null;
    this.modelName = config.modelName || 'samuelolubukun/pii-ner-edge-optimized';
  }

  /**
   * Warm up and load the client-side ONNX model in the browser.
   * Downloads the model weights to the local browser cache.
   */
  async loadModel() {
    if (this.nerPipeline) return;
    this.nerPipeline = await pipeline('token-classification', this.modelName, {
      model_file_name: 'model_quantized'
    });
  }

  /**
   * Analyze input text and identify all PII entities using hybrid Tier 1 and Tier 2.
   * @param {string} text - The input text to check
   * @param {object} options - Custom options (e.g. minScore threshold)
   */
  async analyze(text, options = {}) {
    const minScore = options.minScore || 0.5;
    
    // Tier 1: Local Regex & Checksum Engine
    const localMatches = this.detector.detect(text, { minScore });
    let finalMatches = [...localMatches];

    // Tier 2: Transformers.js Pipeline (if loaded)
    if (this.nerPipeline) {
      try {
        const mlMatchesRaw = await this.nerPipeline(text);
        const mlMatches = this.parseMlMatches(text, mlMatchesRaw);
        finalMatches = this.combineAndDeduplicate(text, localMatches, mlMatches);
      } catch (e) {
        console.warn("PII Warden: Client-side ML inference failed, falling back to local engine:", e);
      }
    }

    // Generate redacted output
    const anonymized = this.anonymizeText(text, finalMatches);

    return {
      originalText: text,
      redactedText: anonymized.text,
      entities: finalMatches,
      replacements: anonymized.replacements
    };
  }

  /**
   * Reconstructs and aggregates raw subwords/tokens from Transformers.js pipeline
   * into clean, boundary-expanded entity objects.
   */
  parseMlMatches(text, mlEntitiesRaw) {
    let currentEntity = null;
    const mlEntities = [];
    let searchIndex = 0;
    
    for (const token of mlEntitiesRaw) {
      let word = token.word.replace(/^(##| | )/, '');
      let start = token.start;
      let end = token.end;
      
      if (start === undefined) {
        start = text.toLowerCase().indexOf(word.toLowerCase(), searchIndex);
        if (start !== -1) {
          end = start + word.length;
          searchIndex = end;
        } else {
          continue;
        }
      } else {
        searchIndex = end;
      }

      let entityGroup = token.entity_group || token.entity;
      let baseEntityGroup = entityGroup.replace(/^(B-|I-)/, '');
      if (baseEntityGroup === 'O') continue;
      
      const isAdjacent = currentEntity !== null && (start <= currentEntity.end + 2);
      const hasSpace = currentEntity !== null && /\s/.test(text.substring(currentEntity.end, start));
      const isSameWord = currentEntity !== null && !hasSpace;
      let isSameType = currentEntity !== null && (currentEntity.entity_group === baseEntityGroup || isSameWord);

      if (!currentEntity || !isSameType || !isAdjacent) {
        if (currentEntity) mlEntities.push(currentEntity);
        currentEntity = {
          entity_group: baseEntityGroup,
          word: text.substring(start, end),
          start: start,
          end: end,
          score: token.score,
          source: 'ml'
        };
      } else {
        currentEntity.end = end;
        currentEntity.word = text.substring(currentEntity.start, currentEntity.end);
        currentEntity.score = Math.min(currentEntity.score, token.score);
      }
    }
    if (currentEntity) mlEntities.push(currentEntity);
    
    // Word Boundary Expansion: Expand ML detections to full words
    const finalMl = [];
    for (let ent of mlEntities) {
      // Skip O tags or undefined entries
      if (!ent || ent.entity_group === 'O') continue;

      while (ent.start > 0 && /[a-zA-Z0-9À-ÿ]/.test(text[ent.start - 1])) {
        ent.start--;
      }
      while (ent.end < text.length && /[a-zA-Z0-9À-ÿ]/.test(text[ent.end])) {
        ent.end++;
      }
      ent.word = text.substring(ent.start, ent.end);
      
      finalMl.push(ent);
    }

    return finalMl;
  }

  /**
   * Merges overlapping local regex matches and ML model predictions.
   */
  combineAndDeduplicate(text, regexes, mls) {
    let combined = [...regexes];
    
    mls.forEach(ml => {
      let entityGroup = ml.entity_group || ml.entity || '';
      let baseGroup = entityGroup.replace(/^(B-|I-)/, '');
      if (baseGroup === 'O') return;

      const mlMatch = {
        entity_type: baseGroup.toUpperCase(),
        start: ml.start,
        end: ml.end,
        text: ml.word || text.substring(ml.start, ml.end),
        score: ml.score || 0.9
      };

      // Check for overlap
      const overlapIdx = combined.findIndex(rgx => Math.max(rgx.start, mlMatch.start) < Math.min(rgx.end, mlMatch.end));
      if (overlapIdx !== -1) {
        const rgx = combined[overlapIdx];
        if (mlMatch.score >= 0.5) {
          // ML overrides or expands regex match boundaries
          combined[overlapIdx] = {
            entity_type: mlMatch.entity_type,
            start: Math.min(rgx.start, mlMatch.start),
            end: Math.max(rgx.end, mlMatch.end),
            text: text.substring(Math.min(rgx.start, mlMatch.start), Math.max(rgx.end, mlMatch.end)),
            score: mlMatch.score
          };
        }
      } else {
        combined.push(mlMatch);
      }
    });
    
    return combined;
  }

  /**
   * Replaces found entities with formatted placeholders.
   */
  anonymizeText(text, entities) {
    let sorted = [...entities].sort((a, b) => b.start - a.start);
    let output = text;
    let replacements = [];
    let typeIndices = {};

    sorted.forEach(ent => {
      const rawType = ent.entity_type.toUpperCase();
      let label = rawType;
      
      if (rawType.startsWith('ID_NUMBER_') || rawType.includes('NIF') || rawType.includes('NIE') || rawType.includes('NINO') || rawType.includes('SSN') || rawType.includes('PPS') || rawType.includes('INSEE') || rawType.includes('CURP') || rawType.includes('RFC') || rawType.includes('NRIC') || rawType.includes('PAN') || rawType.includes('UEN') || rawType.includes('GSTIN') || rawType.includes('PASSPORT') || rawType.includes('LICENSE')) {
        label = 'ID';
      } else if (rawType.includes('CARD')) {
        label = 'CARD';
      } else if (rawType.includes('EMAIL')) {
        label = 'EMAIL';
      } else if (rawType.includes('PHONE')) {
        label = 'PHONE';
      } else {
        label = 'ID';
      }

      if (!typeIndices[label]) typeIndices[label] = 1;
      const placeholder = `[${label}_${typeIndices[label]++}]`;
      output = output.substring(0, ent.start) + placeholder + output.substring(ent.end);
      
      replacements.push({
        original: ent.text,
        replacement: placeholder,
        type: ent.entity_type,
        start: ent.start,
        end: ent.end
      });
    });

    return { text: output, replacements: replacements.reverse() };
  }
}

export default PIIWarden;
