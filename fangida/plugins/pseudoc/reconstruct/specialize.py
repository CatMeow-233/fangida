"""Bounded CFG specialization from typed IR constants and private frame stores.

No decoder, binary-memory reader or assembly interpreter is used. Unknown
branches retain both edges. Calls/opaque effects invalidate memory facts.
The input snapshot is immutable; provenance maps every cloned row back to it.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from collections import deque

from .cfg import build_cfg, cfg_view, reachable
from .stack import parse_address, _address_tree
from ..microcode.ir import Expression, constant
from ..microcode.evaluate import evaluate_expression, UnknownValue, integer_flags, logic_flags
from ..microcode.conditions import evaluate_condition


@dataclass(frozen=True)
class FrameAddress:
    offset: int


def _value(expression, registers, memory):
    op, width = expression['opcode'], expression.get('width', 64)
    if op == 'register':
        if expression['name'] not in registers:
            raise UnknownValue('Unknown register')
        return registers[expression['name']]
    if op == 'constant':
        return expression['value']
    if op == 'address':
        def visit(node):
            if isinstance(node, ast.Name) and node.id in registers:
                return registers[node.id]
            if isinstance(node, ast.Constant) and type(node.value) is int:
                return node.value
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                return -visit(node.operand)
            if isinstance(node, ast.BinOp):
                return arithmetic({ast.Add:'add',ast.Sub:'sub',ast.Mult:'mul'}[type(node.op)],visit(node.left),visit(node.right))
            raise UnknownValue('Unknown address')
        return visit(_address_tree(expression.get('name','')))
    args = [_value(arg,registers,memory) for arg in expression.get('args',())]
    if op == 'load':
        if not isinstance(args[0],FrameAddress) or (args[0].offset,width) not in memory:
            raise UnknownValue('Unknown memory')
        return memory[(args[0].offset,width)]
    if any(isinstance(arg,FrameAddress) for arg in args):
        if op in {'add','sub'}:
            # A wrapped negative immediate is a signed pointer displacement.
            right=args[1]; right=right-(1<<width) if type(right) is int and right&(1<<(width-1)) else right
            return arithmetic(op,args[0],right)
        raise UnknownValue('Unsupported symbolic pointer operation')
    return evaluate_expression(Expression(op,width,tuple(constant(arg, child['width']) for arg,child in zip(args,expression.get('args',()))),
        value=expression.get('value'),name=expression.get('name',''),domain=expression.get('domain','bitvector')))


def arithmetic(op,left,right):
    if isinstance(left,FrameAddress) and type(right) is int and op in {'add','sub'}:
        return FrameAddress(left.offset+(right if op=='add' else -right))
    if type(left) is int and type(right) is int:
        return {'add':lambda:left+right,'sub':lambda:left-right,'mul':lambda:left*right}[op]()
    raise UnknownValue('Unknown pointer arithmetic')


def _rewrite(expression, registers, memory):
    # Loads remain effects in source IR. Only their register consumers can
    # become constants after a matching exact-width private-frame write.
    if expression.get('domain','bitvector') != 'bitvector' or expression['opcode'] in {'address','load'}:
        return deepcopy(expression)
    try:
        value=_value(expression,registers,memory)
        if type(value) is int:
            return constant(value,expression['width']).to_dict()
    except (UnknownValue, KeyError, ValueError, TypeError, OverflowError):
        pass
    result=deepcopy(expression)
    if 'args' in result:
        result['args']=[_rewrite(arg,registers,memory) for arg in result['args']]
    return result


# ---------------------------------------------------------------------------
# 试探（dry run）模式：绝大多数函数最终 no_proven_branch，克隆行与重写表达式全部被丢弃。
# 先在只读模式下跑同一套抽象解释；只有证明了分支（或输入不满足“朴素树”前提）时，
# 才用原始算法（逐行 deepcopy + _rewrite）重新完整执行一遍，因此输出逐字节不变。
# ---------------------------------------------------------------------------

# deepcopy 对这些精确类型直接返回原对象，不会抛异常。
_ATOMIC_TYPES = frozenset({str, int, float, bool, type(None)})
# 容器嵌套上限：保证原算法里的 deepcopy/_rewrite 递归不会因深度而触发 RecursionError。
_MAX_PLAIN_DEPTH = 64
# 需要回退到原算法（deepcopy 版本）时的哨兵：输入不满足朴素树前提或试探中出现异常。
_REBUILD = object()
# 试探证明了分支：所有访问过的行都是朴素树，完整构建可用等价的结构复制代替 deepcopy。
_PROVEN = object()


def _plain_row(row):
    """行是否为“朴素树”：精确 dict/list/tuple 容器、原子叶子、无共享的可变容器、深度有界。

    满足时：原算法对该行的 deepcopy 不会抛异常、得到无别名的结构副本；
    原算法对副本的写入（row/operation/attributes/condition 都是精确 dict，operations 是精确 list）
    也不会抛异常，且被写的容器只有一条访问路径，后续读取不会观察到这些写入。
    """
    if type(row) is not dict:
        return False
    operations = row.get('operations')
    if type(operations) is not list:
        return False
    for operation in operations:
        if type(operation) is not dict:
            return False
        if 'attributes' in operation:
            attributes = operation['attributes']
            if type(attributes) is not dict:
                return False
            if 'condition' in attributes and type(attributes['condition']) is not dict:
                return False
    # 按层遍历容器（叶子就地检查，不入栈），层数即嵌套深度。
    atomic = _ATOMIC_TYPES
    seen = set()
    level = [row]
    depth = 0
    while level:
        if depth > _MAX_PLAIN_DEPTH:
            return False
        following = []
        push = following.append
        for item in level:
            if type(item) is dict:
                marker = id(item)
                if marker in seen:
                    return False
                seen.add(marker)
                for key, value in item.items():
                    if type(key) not in atomic:
                        return False
                    kind = type(value)
                    if kind not in atomic:
                        if kind is dict or kind is list or kind is tuple:
                            push(value)
                        else:
                            return False
            else:
                if type(item) is list:
                    # 元组不可变：共享无害，只登记可变容器；其中的可变容器仍会被检查。
                    marker = id(item)
                    if marker in seen:
                        return False
                    seen.add(marker)
                for value in item:
                    kind = type(value)
                    if kind not in atomic:
                        if kind is dict or kind is list or kind is tuple:
                            push(value)
                        else:
                            return False
        level = following
        depth += 1
    return True


def _clone_plain(item):
    """朴素树的结构复制，结果与 copy.deepcopy 完全相同（无别名、精确类型，备忘表不起作用）。

    元组与 deepcopy 一样：元素复制后全部是原对象时返回原元组。
    """
    kind = type(item)
    if kind is dict:
        return {key: _clone_plain(value) for key, value in item.items()}
    if kind is list:
        return [_clone_plain(value) for value in item]
    if kind is tuple:
        copied = tuple(_clone_plain(value) for value in item)
        return item if all(new is old for new, old in zip(copied, item)) else copied
    return item


def _rewrite_plain(expression, registers, memory):
    """_rewrite 在朴素树上的等价实现：deepcopy 换成结构复制，且不再复制随后被替换掉的 args。"""
    if expression.get('domain','bitvector') != 'bitvector' or expression['opcode'] in {'address','load'}:
        return _clone_plain(expression)
    try:
        value=_value(expression,registers,memory)
        if type(value) is int:
            return constant(value,expression['width']).to_dict()
    except (UnknownValue, KeyError, ValueError, TypeError, OverflowError):
        pass
    if 'args' not in expression:
        return _clone_plain(expression)
    result={key:(None if key=='args' else _clone_plain(value)) for key,value in expression.items()}
    result['args']=[_rewrite_plain(arg,registers,memory) for arg in expression['args']]
    return result


def _probe(expression, registers, memory):
    """与 _rewrite 走完全相同的读取/求值路径、抛出相同的异常，但不复制、不构建结果。

    对朴素树而言，_rewrite 中被省略的 deepcopy 与 constant(...).to_dict() 都不会抛异常。
    """
    if expression.get('domain','bitvector') != 'bitvector' or expression['opcode'] in {'address','load'}:
        return
    try:
        value=_value(expression,registers,memory)
        if type(value) is int:
            constant(value,expression['width'])
            return
    except (UnknownValue, KeyError, ValueError, TypeError, OverflowError):
        pass
    if 'args' in expression:
        for arg in expression['args']:
            _probe(arg,registers,memory)


def _cumulative_addresses(records, cursor):
    """{row['addr']: cursor+sum(r['size'] for r in records[:index])}，用前缀和代替逐行重算（原为平方复杂度）。

    求值顺序与原字典推导式一致：先取键，再从 0 起按顺序累加此前各行的 size。
    """
    result={}
    offset=0
    for index,row in enumerate(records):
        key=row['addr']
        if index:
            offset=offset+records[index-1]['size']
        result[key]=cursor+offset
    return result


def specialize(records, entry, abi, *, max_rows=512, max_states=128):
    blocks=reachable(cfg_view(records),entry)
    if not blocks:
        return records,entry,{'applied':False}
    try:
        outcome=_explore(records,entry,abi,blocks,max_rows,max_states,build=False)
    except Exception:
        # 异常输入：交给原算法，按原样产生结果或抛出同样的异常。
        outcome=_REBUILD
    if outcome is _PROVEN:
        # 同一探索过程访问的行都已验证为朴素树：结构复制与 deepcopy 结果相同。
        return _explore(records,entry,abi,blocks,max_rows,max_states,build=True,plain=True)
    if outcome is not _REBUILD:
        return outcome
    return _explore(records,entry,abi,blocks,max_rows,max_states,build=True)


def _explore(records, entry, abi, blocks, max_rows, max_states, *, build, plain=False):
    """build=True 时就是原来的 specialize 主体；build=False 为只读试探。

    试探模式下：不克隆行、不写任何输入对象、用 _probe 代替 _rewrite（保持异常行为），
    状态演化与原算法完全一致。证明了分支时返回 _PROVEN；遇到不满足朴素树前提的行返回 _REBUILD。
    plain=True（仅在试探已验证全部访问行时使用）以结构复制代替 deepcopy，结果相同。
    """
    clone=_clone_plain if plain else deepcopy
    rewrite=_rewrite_plain if plain else _rewrite
    initial=({abi.stack_pointer:FrameAddress(0)}, {}, None)
    queue=deque(); identifiers={}; results={}; proven=0; total=0
    base=max(row['addr']+row['size'] for row in records)+0x1000
    stride=max(sum(row['size'] for row in b.records) for b in blocks.values())+16
    checked_rows={}
    def state_key(address, state):
        registers,memory,flags=state
        return address,tuple(sorted(registers.items())),tuple(sorted(memory.items())),tuple(sorted((flags or {}).items()))
    def enqueue(address,state):
        if address not in blocks:
            return None
        key=state_key(address,state)
        if key not in identifiers:
            if len(identifiers)>=max_states:
                raise UnknownValue('State budget')
            identifiers[key]=base+len(identifiers)*stride
            queue.append((key,state))
        return identifiers[key]
    try:
        new_entry=enqueue(entry,initial)
        while queue:
            key, incoming=queue.popleft(); address=key[0]; block=blocks[address]
            registers,memory,flags=dict(incoming[0]),dict(incoming[1]),incoming[2]
            rows=[]; condition=None; cursor=identifiers[key]
            originals=_cumulative_addresses(block.records,cursor)
            for original in block.records:
                if build:
                    row=clone(original); row['original_address']=original['addr'];row['addr']=cursor;cursor+=row['size']
                else:
                    checked=checked_rows.get(id(original))
                    if checked is None:
                        checked=checked_rows[id(original)]=_plain_row(original)
                    if not checked:
                        return _REBUILD
                    row=original; original['addr'];cursor+=row['size']
                for operation in row['operations']:
                    opcode=operation['opcode']; attrs=operation.get('attributes',{}); inputs=operation.get('inputs',())
                    before=dict(registers); replaced=False
                    try:
                        if opcode=='assign':
                            value=_value(operation['expression'],registers,memory)
                            root=operation['output']; width=attrs.get('destination_width',operation['width']); storage=attrs.get('storage_width',width)
                            if isinstance(value,FrameAddress):
                                if width!=storage:
                                    raise UnknownValue('Narrow pointer')
                                if build:
                                    attrs['proven_frame_offset']=value.offset
                            elif width<storage and not attrs.get('zero_upper'):
                                shift=attrs.get('bit_offset',0); mask=((1<<width)-1)<<shift
                                if type(registers.get(root)) is not int:
                                    raise UnknownValue('Unknown preserved bits')
                                value=(registers[root]&~mask)|((value&((1<<width)-1))<<shift)
                            else:
                                value&=(1<<width)-1
                            registers[root]=value
                        elif opcode=='store':
                            destination=_value(inputs[0],registers,memory); value=_value(inputs[1],registers,memory)
                            if not isinstance(destination,FrameAddress):
                                raise UnknownValue('Unknown store alias')
                            start=destination.offset; width=operation['width']
                            memory={k:v for k,v in memory.items() if not (k[0]<start+width//8 and start<k[0]+k[1]//8)}
                            memory[(start,width)]=value
                        elif opcode in {'compare','flags_sub','flags_add'}:
                            left,right=(_value(expr,registers,memory) for expr in inputs)
                            if type(left) is not int or type(right) is not int or attrs.get('carry'):
                                raise UnknownValue('Unknown flags')
                            flags=integer_flags(attrs.get('flag_family',attrs.get('family','arm')), 'add' if opcode=='flags_add' else 'sub',left,right,operation['width'])
                        elif opcode in {'test','flags_logic'}:
                            values=[_value(expr,registers,memory) for expr in inputs]
                            value=values[0]&values[1] if opcode=='test' else values[0]
                            flags=logic_flags(attrs.get('flag_family',attrs.get('family','arm')),value,operation['width'])
                        elif opcode in {'select','set_condition'}:
                            selected=evaluate_condition(attrs['condition'],flags=flags) if flags is not None else None
                            if selected is None or attrs.get('false_operation') not in {None,'csel'}:
                                raise UnknownValue('Unknown selection')
                            value=_value(inputs[0 if selected else 1],registers,memory) if opcode=='select' else int(selected)
                            registers[operation['output']]=value
                            expression=constant(value,operation['width']).to_dict()
                            if build:
                                operation.update(opcode='assign',expression=expression,inputs=[expression])
                            replaced=True
                        elif opcode=='branch':
                            pred=attrs['condition']
                            if pred.get('kind')=='zero_test':
                                value=_value(pred['value'],registers,memory)
                                condition=(value==0) if pred['relation']=='eq' else (value!=0)
                            elif flags is not None:
                                condition=evaluate_condition(pred,flags=flags)
                        elif opcode=='address_writeback':
                            value=_value({'opcode':'address','width':abi.word*8,'name':attrs['address']},registers,memory)
                            if attrs['mode']=='post_index':
                                value=arithmetic('add',value,int(str(attrs['offset']).lstrip('#'),0))
                            registers[operation['output']]=value
                        elif opcode in {'call','opaque','system_transition'}:
                            volatile = tuple(abi.volatile)+tuple(root for root in registers if root.startswith(('v','xmm')))
                            for root in (volatile if opcode=='call' and abi.volatile else tuple(registers)):
                                registers.pop(root,None)
                            memory.clear();flags=None
                        elif opcode not in {'jump','return','discard','nop','trap'}:
                            raise UnknownValue('Unsupported operation')
                    except (UnknownValue, KeyError, ValueError, TypeError, OverflowError):
                        affected=set(attrs.get('outputs',()))
                        unmodelled=opcode not in {'assign','store','compare','flags_sub','flags_add','test','flags_logic','select','set_condition','branch','address_writeback','call','opaque','system_transition','jump','return','discard','nop','trap'}
                        if unmodelled:
                            affected.update(original.get('writes',()))
                        for root in affected:
                            registers.pop(root,None)
                        if operation.get('output'):registers.pop(operation['output'],None)
                        if opcode=='store':memory.clear()
                        if opcode.startswith('flags_') or opcode in {'compare','test','flag_write','compare_float','compare_add','conditional_compare','bit_test'}:flags=None
                        if unmodelled:
                            # 未建模的操作（bt/bts/btr/btc 的 bit_test 与内存形式 bit_modify、rcl/rcr、cmpxchg、
                            # 串操作…）：所在行改写标志就丢弃已知标志（否则后续 jcc 会按过期的标志被“证明”），
                            # 所在行写内存就清空已知的栈槽内容（否则后续读取会得到写入前的旧值）。
                            if 'flags' in original.get('writes',()) or original.get('flag_effect','preserve')!='preserve':flags=None
                            if original.get('memory_effect') in {'write','read_write'}:memory.clear()
                    if build:
                        for field in ('expression',):
                            if field in operation:operation[field]=rewrite(operation[field],before,memory)
                        operation['inputs']=[rewrite(expr,before,memory) for expr in operation.get('inputs',())]
                    elif not replaced:
                        # 被 select/set_condition 改写成常量的操作，原算法重写的是常量，不会抛异常。
                        if 'expression' in operation:_probe(operation['expression'],before,memory)
                        for expr in operation.get('inputs',()):_probe(expr,before,memory)
                    if opcode=='assign' and isinstance(registers.get(operation.get('output')),FrameAddress):
                        if build:
                            attrs['proven_frame_offset']=registers[operation['output']].offset
                    if attrs.get('condition',{}).get('origin') is not None:
                        if build:
                            attrs['condition']['origin']=originals.get(attrs['condition']['origin'])
                        else:
                            originals.get(attrs['condition']['origin'])
                rows.append(row)
            state=(registers,memory,flags)
            successors=block.successors
            if block.terminal=='branch' and condition is not None:
                chosen=successors[0 if condition else 1]; target=enqueue(chosen,state)
                operation=rows[-1]['operations'][-1]
                old_attributes = operation.get('attributes', {})
                attributes = {'target':target,'proven_condition':bool(condition)}
                if target is None:
                    attributes['external_target'] = old_attributes.get('external_target' if condition else 'external_fallthrough', old_attributes.get('target' if condition else 'fallthrough'))
                    if not condition:
                        attributes['frontier_kind'] = 'fallthrough'
                if build:
                    operation.update(opcode='jump',inputs=[],attributes=attributes)
                proven+=1
            elif successors:
                targets=[enqueue(child,state) for child in successors]
                if block.terminal=='branch':
                    attributes = rows[-1]['operations'][-1]['attributes']
                    if build:
                        if targets[0] is None:
                            attributes['external_target'] = attributes.get('external_target', attributes.get('target'))
                        if targets[1] is None:
                            attributes['external_fallthrough'] = attributes.get('external_fallthrough', attributes.get('fallthrough'))
                        attributes.update(target=targets[0],fallthrough=targets[1])
                    else:
                        targets[1]
                elif block.terminal=='jump':
                    attributes = rows[-1]['operations'][-1]['attributes']
                    if build:
                        if targets[0] is None:
                            attributes['external_target'] = attributes.get('external_target', attributes.get('target'))
                        attributes['target']=targets[0]
                else:
                    attributes = {'target':targets[0]}
                    if targets[0] is None:
                        attributes.update(external_target=(rows[-1]['original_address'] if build else rows[-1]['addr']) + rows[-1]['size'], frontier_kind='fallthrough')
                    if build:
                        rows[-1]['operations'].append({'opcode':'jump','width':0,'inputs':[],'attributes':attributes})
            total+=len(rows)
            if total>max_rows:raise UnknownValue('Source row budget')
            results[identifiers[key]]=rows
        if not proven:
            return records,entry,{'applied':False,'reason':'no_proven_branch'}
        if not build:
            return _PROVEN
        return [row for address in sorted(results) for row in results[address]],new_entry,{'applied':True,'proven_branches':proven,
            'source_states':len(results),'source_instructions':total,'original_instructions':len(records),
            'provenance':[{'address':row['addr'],'original_address':row['original_address']} for rows in results.values() for row in rows]}
    except UnknownValue as exc:
        return records,entry,{'applied':False,'reason':str(exc),'source_states':len(identifiers),'processed_instructions':total}
