"""ARM64 真实混淆快照、微码语义与源码编译执行回归。"""
from __future__ import annotations
import ast
import copy
import json
from pathlib import Path
import unittest

from tests.test_pseudoc import instruction as ins, function as fn
from tests.test_reconstruction import compile_run
from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import lift_instruction, evaluate_expression, Expression, constant, integer_flags
from fangida.plugins.pseudoc.microcode.conditions import evaluate_condition
from fangida.plugins.pseudoc.reconstruct.specialize import specialize
from fangida.plugins.pseudoc.reconstruct.abi import select_abi

FIXTURE=Path(__file__).parent/'fixtures'/'tersafe_tss_unity_is_enable.json'


def run_original_ir(records, length, outcome):
    registers={f'x{i}':0 for i in range(31)}
    registers.update(sp=0x100000,x0=0x200000,x1=length)
    memory={};flags={};trace=[];rows={row['addr']:row for row in records}
    def address(node):
        if isinstance(node,ast.Constant):return node.value
        if isinstance(node,ast.Name):return registers[node.id]
        if isinstance(node,ast.UnaryOp):return -address(node.operand)
        left,right=address(node.left),address(node.right)
        return left+right if isinstance(node.op,ast.Add) else left-right if isinstance(node.op,ast.Sub) else left*right
    def value(expr):
        opcode,width=expr['opcode'],expr['width'];mask=(1<<width)-1
        if opcode=='register':return registers[expr['name']]&mask
        if opcode=='constant':return expr['value']&mask
        if opcode=='address':return address(ast.parse(expr['name'],mode='eval').body)&mask
        if opcode=='load':
            at=value(expr['args'][0]);return sum(memory.get(at+i,0)<<(i*8) for i in range(width//8))
        args=tuple(constant(value(child),child['width']) for child in expr.get('args',()))
        return evaluate_expression(Expression(opcode,width,args,value=expr.get('value'),name=expr.get('name','')))
    cursor=records[0]['addr']
    for _ in range(1024):
        row=rows[cursor];following=cursor+row['size']
        for operation in row['operations']:
            opcode=operation['opcode'];attrs=operation.get('attributes',{});inputs=operation.get('inputs',())
            if opcode=='assign':
                number=value(operation['expression']);root=operation['output'];width=attrs['destination_width'];storage=attrs['storage_width'];shift=attrs.get('bit_offset',0)
                if attrs.get('zero_upper') or width==storage:registers[root]=number&((1<<width)-1)
                else:
                    mask=((1<<width)-1)<<shift;registers[root]=(registers[root]&~mask)|((number<<shift)&mask)
            elif opcode=='store':
                at,number=value(inputs[0]),value(inputs[1])
                for index in range(operation['width']//8):memory[at+index]=(number>>(index*8))&255
            elif opcode=='compare':flags=integer_flags('arm','sub',value(inputs[0]),value(inputs[1]),operation['width'])
            elif opcode=='select':
                decision=evaluate_condition(attrs['condition'],flags=flags)
                registers[operation['output']]=value(inputs[0 if decision else 1])
            elif opcode=='address_writeback':
                number=address(ast.parse(attrs['address'],mode='eval').body)
                registers[operation['output']]=number+(int(attrs['offset'].lstrip('#'),0) if attrs['mode']=='post_index' else 0)
            elif opcode=='branch':following=attrs['target'] if evaluate_condition(attrs['condition'],flags=flags) else attrs['fallthrough']
            elif opcode=='jump':following=attrs['target']
            elif opcode=='call':
                target=attrs['target'];arguments=tuple(registers[f'x{i}'] for i in range(4));trace.append((target,arguments))
                if target==0x50e020:
                    dest,source,count,capacity=arguments
                    assert source==0x200000 and count==min(length&0xffffffff,63) and capacity==64
                    assert all(memory.get(dest+i,0)==0 for i in range(64))
                    for i in range(count):memory[dest+i]=i+1
                    returned=dest
                elif target==0x22d820:returned=0x12345678
                elif target==0x22da98:
                    owner,buffer,zero,one=arguments
                    assert owner==0x12345678 and zero==0 and one==1
                    assert all(memory.get(buffer+i,0)==i+1 for i in range(min(length&0xffffffff,63)))
                    returned=outcome
                else:raise AssertionError('非预期调用')
                for i in range(19):registers[f'x{i}']=0xbad000+i
                registers['x0']=returned;flags={}
            elif opcode=='return':return registers['x0'],trace
            elif opcode=='discard':value(inputs[0])
            else:raise AssertionError(opcode)
        cursor=following
    raise AssertionError('微码路径未在预算内终止')


class ARM64RecoveryTests(unittest.TestCase):
    def test_wide_moves_keep_only_selected_halfword_and_zero_upper(self):
        for mnemonic, operands, old, expected in (
            ('movk',('w8','#0x1234','lsl #16'),0xffff0000abcdfedc,0x1234fedc),
            ('movk',('x8','#0x1234','lsl #32'),0xffffaaaabbbbcccc,0xffff1234bbbbcccc),
            ('movn',('w8','#0'),0xffffffffffffffff,0xffffffff),
            ('movz',('x8','#0x1234','lsl #48'),0xffffffffffffffff,0x1234000000000000)):
            with self.subTest(mnemonic=mnemonic,operands=operands):
                row=lift_instruction(ins(0,mnemonic,*operands),'arm64')
                self.assertTrue(row['supported'])
                operation=row['operations'][0]
                self.assertEqual(evaluate_expression(operation['expression'],{'x8':old}),expected)
                self.assertEqual(row['flag_effect'],'preserve')
        for operands in (('w8','#0x10000'),('w8','#1','lsl #32'),('sp','#1')):
            self.assertFalse(lift_instruction(ins(0,'movk',*operands),'arm64')['supported'])

    def test_unscaled_memory_widths_and_negative_offsets(self):
        for mnemonic,register,width,opcode in (('ldur','w0',32,'assign'),('ldursb','x0',8,'assign'),('stur','x0',64,'store'),('sturb','w0',8,'store')):
            with self.subTest(mnemonic=mnemonic):
                row=lift_instruction(ins(0,mnemonic,register,'[x29, #-4]'),'arm64')
                self.assertTrue(row['supported']);self.assertEqual(row['operations'][0]['opcode'],opcode)
        self.assertFalse(lift_instruction(ins(0,'stur','w0','[sp, #-4]!'),'arm64')['supported'])

    def test_inverted_logic_keeps_bitvector_semantics(self):
        for mnemonic,expected in (('orn',(0x5555|~0x3333)&0xffffffff),('bic',0x5555&~0x3333),('eon',(0x5555^~0x3333)&0xffffffff)):
            row=lift_instruction(ins(0,mnemonic,'w0','w1','w2'),'arm64')
            self.assertTrue(row['supported']);self.assertEqual(evaluate_expression(row['operations'][0]['expression'],{'x1':0x5555,'x2':0x3333}),expected)

    def test_vector_zero_and_pair_memory_are_typed_128_bits(self):
        for instruction in (ins(0,'movi','v0.2d','#0000000000000000'),ins(1,'stp','q0','q0','[x8, #32]'),ins(2,'ldp','q0','q1','[x8]')):
            row=lift_instruction(instruction,'arm64');self.assertTrue(row['supported']);self.assertTrue(all(op['width']==128 for op in row['operations']))
        self.assertFalse(lift_instruction(ins(2,'ldp','q0','q0','[x8]'),'arm64')['supported'])

    def test_conditions_across_blocks_keep_unique_flags_and_capture(self):
        function=fn(ins(0,'cmp','edi','esi'),ins(1,'jmp','0x3',kind='jump',target=3),
            ins(3,'mov','edi','7'),ins(4,'jl','0x8',kind='jump',target=8,conditional=True),
            ins(5,'mov','eax','1'),ins(6,'ret',kind='return'),ins(8,'mov','eax','2'),ins(9,'ret',kind='return'),name='cross',pseudoc_context={'kind':'elf'})
        output=generate_pseudoc(function,'x86_64',style='readable')
        self.assertNotIn('unresolved_condition',output.pseudoc)
        compile_run(output.pseudoc,'return cross(-3,1)==2 && cross(3,1)==1 ? 0:1;')

    def test_specialization_keeps_unknown_memory_and_budget_fallback(self):
        function=fn(ins(0,'mov','eax','dword ptr [rdi]'),ins(1,'cmp','eax','0'),ins(2,'je','0x5',kind='jump',target=5,conditional=True),
            ins(3,'ret',kind='return'),ins(5,'ret',kind='return'),pseudoc_context={'kind':'elf'})
        machine=generate_pseudoc(function,'x86_64');before=copy.deepcopy(machine.microcode)
        records,entry,report=specialize(machine.microcode,0,select_abi('x86_64',{'kind':'elf'}),max_states=1)
        self.assertFalse(report['applied']);self.assertEqual(records,list(before) if isinstance(records,list) else before);self.assertEqual(machine.microcode,before)
        output=generate_pseudoc(function,'x86_64',style='readable')
        self.assertIn('if (',output.pseudoc)

    def test_nested_pair_addresses_use_byte_units(self):
        function=fn(ins(0,'stp','w1','w2','[x0, #-52]'),ins(1,'ret',kind='return'),pseudoc_context={'kind':'elf'},name='pair',
            prototype={'return_type':'void','parameters':[{'register':'x0','type':'uint32_t *'},{'register':'x1','type':'uint32_t'},{'register':'x2','type':'uint32_t'}]})
        output=generate_pseudoc(function,'arm64',style='readable')
        self.assertNotIn('arg_1 +',output.pseudoc)
        compile_run(output.pseudoc,'uint32_t a[32]={0};pair(a+16,3,9);return a[3]==3 && a[4]==9 ? 0:1;')

    def test_real_snapshot_removes_dispatcher_without_changing_machine_snapshot(self):
        function=json.loads(FIXTURE.read_text());before=copy.deepcopy(function)
        output=generate_pseudoc(function,'arm64',style='readable')
        self.assertEqual(function,before);self.assertEqual(len(output.microcode),255)
        self.assertTrue(all(row['supported'] for row in output.microcode))
        self.assertNotRegex(output.pseudoc,r'goto|unresolved_operation|unresolved_condition|unknown_value|while\s*\(')
        self.assertIn('uint32_t tss_unity_is_enable(uint64_t arg_1, uint32_t arg_2)',output.pseudoc)
        self.assertIn('memset(',output.pseudoc);self.assertLessEqual(len(output.pseudoc.splitlines()),18)
        report=output.reconstruction
        self.assertTrue(report['specialization']['applied']);self.assertEqual(report['specialization']['proven_branches'],20)
        self.assertEqual([call['target'] for call in report['calls']],[0x50e020,0x22d820,0x22da98])
        self.assertEqual({item['kind'] for item in report['unresolved']},{'call_signature'})
        # Independent typed-IR traversal executes the original 255-row CFG.
        for length in (0,1,62,63,64,0xffffffff):
            for outcome in (0,1,2,0x100000003):
                returned,trace=run_original_ir(output.microcode,length,outcome)
                self.assertEqual(returned,outcome&1);self.assertEqual(len(trace),3)
        prefix='''#include <string.h>
static uint32_t wanted_length; static uint64_t wanted_result; static int phase;
uint64_t unknown_arguments(void) { return 0; }
uint64_t unknown_function(uint64_t dest,uint64_t source,uint64_t n,uint64_t cap,uint64_t tail) {
    if (phase++!=0 || source!=42 || n!=(wanted_length<63?wanted_length:63) || cap!=64 || tail) __builtin_trap();
    uint8_t *p=(uint8_t *)(uintptr_t)dest; for(int i=0;i<64;i++) if(p[i]) __builtin_trap();
    for(uint64_t i=0;i<n;i++) p[i]=(uint8_t)(i+1);return dest;
}
uint64_t unknown_function_2(uint64_t previous,uint64_t tail) { if(phase++!=1 || !previous || tail) __builtin_trap();return 0x12345678; }
uint64_t unknown_function_3(uint64_t owner,uint64_t buffer,uint64_t zero,uint64_t one,uint64_t tail) {
    if(phase++!=2 || owner!=0x12345678 || zero || one!=1 || tail) __builtin_trap();
    uint8_t *p=(uint8_t *)(uintptr_t)buffer;uint32_t n=wanted_length<63?wanted_length:63;
    for(uint32_t i=0;i<n;i++) if(p[i]!=(uint8_t)(i+1)) __builtin_trap();return wanted_result;
}
'''
        compile_run(output.pseudoc,'''uint32_t lengths[]={0,1,62,63,64,UINT32_MAX};uint64_t outcomes[]={0,1,2,0x100000003ULL};
for(unsigned a=0;a<6;a++) { for(unsigned b=0;b<4;b++) { wanted_length=lengths[a];wanted_result=outcomes[b];phase=0;
if(tss_unity_is_enable(42,wanted_length)!=(wanted_result&1) || phase!=3) return 1; } }
return 0;''',prefix)


if __name__=='__main__':unittest.main()
