"""真实 tp2 尾转移、入口类型版本和显式部分重建边界。"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import Expression, constant, evaluate_expression
from tests.test_pseudoc import instruction as ins, function as fn
from tests.test_reconstruction import compile_run


FIXTURE = Path(__file__).parent / 'fixtures' / 'tersafe_tp2_dec_tss_info.json'


def fixture():
    snapshot = json.loads(FIXTURE.read_text())
    snapshot['pseudoc_context']['callees'] = {
        int(key): value for key, value in snapshot['pseudoc_context']['callees'].items()}
    return snapshot


def original_zero_transfer(records, arguments):
    """独立遍历原始微码，仅核对 flag=0 的栈恢复和尾转移。"""
    registers = {f'x{i}': 0x700000 + i for i in range(31)}
    registers.update(sp=0x10000)
    original = dict(registers)
    registers.update({f'x{i}': argument for i, argument in enumerate(arguments)})
    memory = {}
    rows = {row['addr']: row for row in records}

    def address(node):
        if isinstance(node, ast.Constant): return node.value
        if isinstance(node, ast.Name): return registers[node.id]
        if isinstance(node, ast.UnaryOp): return -address(node.operand)
        return address(node.left) + address(node.right) if isinstance(node.op, ast.Add) else address(node.left) - address(node.right)

    def value(expression):
        opcode, width = expression['opcode'], expression['width']
        if opcode == 'register': return registers[expression['name']] & ((1 << width) - 1)
        if opcode == 'constant': return expression['value']
        if opcode == 'address': return address(ast.parse(expression['name'], mode='eval').body)
        if opcode == 'load':
            at = value(expression['args'][0])
            return sum(memory.get(at + index, 0) << (8 * index) for index in range(width // 8))
        args = tuple(constant(value(arg), arg['width']) for arg in expression.get('args', ()))
        return evaluate_expression(Expression(opcode, width, args, value=expression.get('value')))

    cursor = records[0]['addr']
    for _ in range(64):
        row = rows[cursor]
        following = cursor + row['size']
        for operation in row['operations']:
            opcode, attrs = operation['opcode'], operation.get('attributes', {})
            if opcode == 'assign':
                number = value(operation['expression'])
                width = attrs['destination_width']
                registers[operation['output']] = number & ((1 << width) - 1)
            elif opcode == 'store':
                at, number = map(value, operation['inputs'])
                for index in range(operation['width'] // 8): memory[at + index] = (number >> (8 * index)) & 255
            elif opcode == 'address_writeback':
                number = address(ast.parse(attrs['address'], mode='eval').body)
                registers[operation['output']] = number + (int(attrs['offset'].lstrip('#'), 0) if attrs['mode'] == 'post_index' else 0)
            elif opcode == 'call':
                if attrs['target'] != 0x2dad4c: raise AssertionError('零分支不应调用其它目标')
                for index in range(19): registers[f'x{index}'] = 0xbad000 + index
                registers['x0'] = 0x200000  # object+940 默认为0。
            elif opcode == 'branch':
                predicate = attrs['condition']
                if predicate['kind'] != 'zero_test': raise AssertionError(predicate)
                following = attrs['target'] if value(predicate['value']) == 0 else attrs['fallthrough']
            elif opcode == 'jump':
                if attrs['target'] != 0x50e1b0: raise AssertionError('零分支应尾转移至SDK PLT')
                for root in ('sp', 'x19', 'x20', 'x21', 'x29', 'x30'):
                    if registers[root] != original[root]: raise AssertionError(f'未恢复 {root}')
                return tuple(registers[f'x{i}'] for i in range(3))
            else: raise AssertionError(opcode)
        cursor = following
    raise AssertionError('零分支未在预算内终止')


class ReconstructionRegionTests(unittest.TestCase):
    def test_real_tp2_retains_all_machine_evidence_and_does_not_fake_returns(self):
        snapshot = fixture()
        before = copy.deepcopy(snapshot)
        result = generate_pseudoc(snapshot, 'arm64', style='readable')
        self.assertEqual(snapshot, before)
        self.assertEqual(len(result.microcode), 36)
        self.assertTrue(all(row['supported'] for row in result.microcode))
        self.assertNotRegex(result.pseudoc, r'unresolved_operation|unresolved_result|unknown_value|arg_7')
        self.assertNotIn('return ', result.pseudoc)
        self.assertIn('uint64_t arg_1, uint64_t arg_2, uint64_t arg_3', result.pseudoc)
        self.assertIn('部分源码重建', result.pseudoc)
        self.assertFalse(result.reconstruction['complete'])
        self.assertFalse(result.reconstruction['source_semantics_complete'])
        self.assertTrue(result.warnings)
        region, = result.reconstruction['machine_regions']
        self.assertEqual(region['entry'], 0x1c40c8)
        self.assertEqual(region['instruction_count'], 19)
        self.assertEqual(region['end'], 0x1c4114)
        self.assertEqual(region['state_contract'], 'original_machine_state_required')
        originals = {row['addr']: row for row in result.microcode}
        for row in region['instructions']: self.assertEqual(row, originals[row['addr']])
        self.assertEqual(region['instructions'][-1]['operations'][0]['attributes']['target_expression']['name'], 'x5')
        self.assertEqual({op['opcode'] for row in region['instructions'] for op in row['operations']} & {'call', 'system_transition', 'store', 'jump'},
                         {'call', 'system_transition', 'store', 'jump'})
        transfer = next(call for call in result.reconstruction['calls'] if call.get('target') == 0x50e1b0)
        self.assertEqual(transfer['name'], 'tss_sdk_dec_tss_info')
        self.assertEqual(transfer['recovered_argument_count'], 3)
        self.assertFalse(transfer['argument_count_known'])

    def test_zero_path_matches_original_ir_and_compiled_source_argument_transfer(self):
        result = generate_pseudoc(fixture(), 'arm64', style='readable')
        values = (0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0x8000000000000000, 0xffffffffffffffff)
        for index, value in enumerate(values):
            args = (value, values[(index + 1) % len(values)], values[(index + 2) % len(values)])
            self.assertEqual(original_zero_transfer(result.microcode, args), args)
        prefix = '''#include <setjmp.h>
static jmp_buf completed; static uint32_t object[236];
static uint64_t expected[3]; static uint32_t returned;
uint64_t unknown_arguments(void) { return 0; }
uint64_t function_2dad4c(uint64_t tail) { if(tail) __builtin_trap(); return (uintptr_t)object; }
uint32_t tss_sdk_dec_tss_info(uint64_t a,uint64_t b,uint64_t c,uint64_t tail) {
    if(a!=expected[0] || b!=expected[1] || c!=expected[2] || tail) __builtin_trap(); return 0xf1234567U;
}
_Noreturn void tail_transfer(uint32_t (*target)(uint64_t,uint64_t,uint64_t,uint64_t),uint64_t a,uint64_t b,uint64_t c,uint64_t tail) {
    if(target!=tss_sdk_dec_tss_info) __builtin_trap(); returned=target(a,b,c,tail); longjmp(completed,1);
}
#define __machine_state_region__(region) __builtin_trap()
'''
        compile_run(result.pseudoc, '''uint64_t values[]={0,1,0x7fffffff,0x80000000,0xffffffff,0x8000000000000000ULL,UINT64_MAX};
for(unsigned i=0;i<7;i++) { expected[0]=values[i];expected[1]=values[(i+1)%7];expected[2]=values[(i+2)%7];
if(!setjmp(completed)) tp2_dec_tss_info(expected[0],expected[1],expected[2]);
if(returned!=0xf1234567U) return 1; } return 0;''', prefix)

    def test_incoming_pointer_type_does_not_come_from_later_call_result(self):
        snapshot = fn(ins(0,'mov','x19','x0',size=4),ins(4,'bl','0x20',size=4,kind='call',target=32),
            ins(8,'ldr','w8','[x0]',size=4),ins(12,'mov','x0','x19',size=4),ins(16,'ret',size=4,kind='return'),
            pseudoc_context={'kind':'elf'})
        result = generate_pseudoc(snapshot,'arm64',style='readable')
        self.assertEqual(result.reconstruction['parameters'][0]['type'],'uint64_t')

    def test_pointer_evidence_follows_incoming_copy_before_call(self):
        snapshot = fn(ins(0,'mov','x19','x0',size=4),ins(4,'bl','0x20',size=4,kind='call',target=32),
            ins(8,'ldr','w0','[x19]',size=4),ins(12,'ret',size=4,kind='return'),pseudoc_context={'kind':'elf'})
        result = generate_pseudoc(snapshot,'arm64',style='readable')
        self.assertEqual(result.reconstruction['parameters'][0]['type'],'uint32_t *')

    def test_overlapping_stack_load_capture_survives_later_store(self):
        snapshot = fn(ins(0,'sub','rsp','16'),ins(1,'mov','word ptr [rsp]','0x1234'),
            ins(2,'movzx','eax','byte ptr [rsp+1]'),ins(3,'mov','byte ptr [rsp+1]','0x56'),
            ins(4,'add','rsp','16'),ins(5,'ret',kind='return'),name='captured_byte',pseudoc_context={'kind':'elf'})
        result = generate_pseudoc(snapshot,'x86_64',style='readable')
        compile_run(result.pseudoc,'return captured_byte()==0x12 ? 0:1;')

    def test_indexed_load_recovers_array_and_signed_extension(self):
        for extension in ('uxtw', 'sxtw'):
            snapshot = fn(ins(0,'ldr','w0',f'[x0, w1, {extension} #2]',size=4),
                ins(4,'ret',size=4,kind='return'),name='indexed',pseudoc_context={'kind':'elf'})
            result = generate_pseudoc(snapshot,'arm64',style='readable')
            self.assertIn('uint32_t * arg_1',result.pseudoc)
            self.assertIn('arg_1[',result.pseudoc)
            self.assertNotIn('unknown_value',result.pseudoc)
            main = 'uint32_t a[]={3,7,11}; return indexed(a,2)==11 ? 0:1;' if extension == 'uxtw' else 'uint32_t a[]={3,7,11}; return indexed(a+1,UINT32_MAX)==3 ? 0:1;'
            compile_run(result.pseudoc,main)


if __name__ == '__main__': unittest.main()
