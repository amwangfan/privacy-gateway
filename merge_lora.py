#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_lora.py - LoRA 权重合并与 HuggingFace 格式导出验证脚本
针对 Qwen/Qwen2.5-0.5B-Instruct + LoRA 进行无损合并，并确保 lm_head 解绑（tie_word_embeddings = False）。

核心特性：
1. 支持直接读取桌面 .zip 压缩包或已解压目录。
2. 支持从 ModelScope（国内推荐）或 HuggingFace 自动下载基座模型，或加载本地基座。
3. 显式解绑 lm_head 与 embed_tokens，并物理隔离权重张量内存指针。
4. 包含严谨的前后 Logits 差异校验（针对 SECRET [65310] vs SAFE [83788]），确保 LoRA 真正合并生效。
5. 自动二次校验保存后的 config.json 中的 tie_word_embeddings 状态。
"""

import os
import sys
import json
import shutil
import zipfile
import tempfile
import argparse
from pathlib import Path
from typing import Tuple, Optional

# 常量定义
TOKEN_ID_SECRET = 65310  # 'SECRET'
TOKEN_ID_SAFE = 83788    # 'SAFE'

DEFAULT_TEST_PROMPT = (
    "判断以下词或短语是否为需要保密的隐私敏感信息"
    "（包括密码、API密钥、访问令牌、私钥等），"
    "仅回答 SECRET 或 SAFE：\nadmin123\n答案："
)


def log(msg: str, level: str = "INFO"):
    prefixes = {
        "INFO": "[INFO]",
        "SUCCESS": "[✓ SUCCESS]",
        "WARN": "[! WARN]",
        "ERROR": "[✗ ERROR]"
    }
    print(f"{prefixes.get(level, '[INFO]')} {msg}")


def locate_adapter_dir(search_root: Path) -> Path:
    """
    在指定目录及其子目录中递归搜索包含 adapter_config.json 的真实 adapter 路径。
    """
    candidates = list(search_root.rglob("adapter_config.json"))
    if not candidates:
        raise FileNotFoundError(f"在 {search_root} 下未找到 adapter_config.json！")
    
    # 优先选择包含 checkpoint 的目录（如果有），或者直接选第一个
    # 例如如果有 checkpoint-204，优先使用 checkpoint-204
    candidates_sorted = sorted(candidates, key=lambda p: (1 if "checkpoint" in str(p) else 0, len(str(p))), reverse=True)
    target_config = candidates_sorted[0]
    adapter_dir = target_config.parent
    log(f"已定位到 LoRA 适配器目录: {adapter_dir}")
    return adapter_dir


def prepare_lora_path(lora_input: str) -> Tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    """
    处理 LoRA 输入路径：如果是 .zip 压缩包，自动解压到临时目录；如果是目录则直接使用。
    """
    lora_path = Path(lora_input).expanduser().resolve()
    if not lora_path.exists():
        raise FileNotFoundError(f"指定的 LoRA 路径不存在: {lora_path}")

    if lora_path.is_file() and lora_path.suffix.lower() == ".zip":
        log(f"检测到 LoRA 压缩包: {lora_path}，正在解压...")
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="lora_extract_")
        extract_root = Path(temp_dir_obj.name)
        with zipfile.ZipFile(lora_path, "r") as zf:
            zf.extractall(extract_root)
        adapter_dir = locate_adapter_dir(extract_root)
        return adapter_dir, temp_dir_obj
    elif lora_path.is_dir():
        adapter_dir = locate_adapter_dir(lora_path)
        return adapter_dir, None
    else:
        raise ValueError(f"不受支持的 LoRA 输入路径类型: {lora_path}")


def download_or_load_base_model(model_name_or_path: str, source: str = "auto") -> str:
    """
    根据 source 配置获取基座模型本地路径（支持 ModelScope 国内高速加速与 HuggingFace）。
    """
    local_path = Path(model_name_or_path).expanduser().resolve()
    if local_path.exists() and local_path.is_dir():
        log(f"使用本地基座模型目录: {local_path}")
        return str(local_path)

    if source in ("modelscope", "auto"):
        try:
            log(f"尝试通过 ModelScope 下载/加载基座模型: {model_name_or_path}...")
            from modelscope import snapshot_download
            model_dir = snapshot_download(model_name_or_path)
            log(f"ModelScope 模型加载成功，缓存路径: {model_dir}", "SUCCESS")
            return model_dir
        except Exception as e:
            if source == "modelscope":
                raise RuntimeError(f"从 ModelScope 下载模型失败: {e}")
            log(f"ModelScope 不可用或下载失败（{e}），回退到 Hugging Face...", "WARN")

    # 回退到 HuggingFace
    log(f"使用 Hugging Face 标识符: {model_name_or_path}")
    return model_name_or_path


def evaluate_test_prompt(model, tokenizer, prompt: str, device: str) -> dict:
    """
    执行单次前向推理（无自回归生成），提取末位 token 处的 Logits 及目标词概率。
    """
    import torch
    import torch.nn.functional as F

    model.eval()
    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        # 获取最后一个输入 token 处的预测 logits，shape: [vocab_size]
        last_token_logits = outputs.logits[0, -1, :].detach().float().cpu()

    secret_logit = float(last_token_logits[TOKEN_ID_SECRET].item())
    safe_logit = float(last_token_logits[TOKEN_ID_SAFE].item())
    diff = secret_logit - safe_logit

    # 计算针对这两个 token 的二分类 softmax 概率
    pair_logits = torch.tensor([secret_logit, safe_logit])
    pair_probs = F.softmax(pair_logits, dim=0)
    prob_secret = float(pair_probs[0].item())
    prob_safe = float(pair_probs[1].item())

    return {
        "all_logits": last_token_logits,
        "secret_logit": secret_logit,
        "safe_logit": safe_logit,
        "diff": diff,
        "prob_secret": prob_secret,
        "prob_safe": prob_safe,
    }


def main():
    parser = argparse.ArgumentParser(description="合并 LoRA 至基座模型并导出解绑后的 HuggingFace 模型")
    parser.add_argument(
        "--lora-path",
        type=str,
        default="privacy-gateway-v3-lora",
        help="LoRA 路径：本地目录、.zip，或先用 huggingface-cli 下载 venti1888/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="Qwen/Qwen2.5-0.5B-Instruct",
        help="基座模型名称或本地路径"
    )
    parser.add_argument(
        "--source",
        type=str,
        choices=["auto", "modelscope", "huggingface", "local"],
        default="auto",
        help="基座模型下载源：auto (优先ModelScope), modelscope, huggingface, local"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./qwen2.5-0.5b-privacy-merged",
        help="合并后 HF 模型的输出目录"
    )
    parser.add_argument(
        "--device",
        type=str,
        default="auto",
        help="运算设备：auto, cuda, cpu"
    )
    parser.add_argument(
        "--test-prompt",
        type=str,
        default=DEFAULT_TEST_PROMPT,
        help="用于融合前后验证差异的测试 Prompt"
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="是否跳过前后的 logits 差异验证（不建议开启）"
    )

    args = parser.parse_args()

    # 1. 检查 PyTorch 及必要依赖
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, AutoConfig
        from peft import PeftModel
    except ImportError as e:
        log(f"缺少关键依赖包: {e}。请先运行: pip install torch transformers peft accelerate safetensors modelscope", "ERROR")
        sys.exit(1)

    # 确定计算设备
    if args.device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = args.device
    log(f"使用计算设备: {device} (PyTorch {torch.__version__})")

    # 2. 准备 LoRA 路径（解压 zip 或定位文件夹）
    temp_dir_obj = None
    try:
        adapter_dir, temp_dir_obj = prepare_lora_path(args.lora_path)

        # 读取 adapter_config.json 查看配置
        adapter_cfg_file = adapter_dir / "adapter_config.json"
        with open(adapter_cfg_file, "r", encoding="utf-8") as f:
            adapter_cfg = json.load(f)
        log(f"LoRA 配置信息: target_modules={adapter_cfg.get('target_modules')}, r={adapter_cfg.get('r')}, alpha={adapter_cfg.get('lora_alpha')}")
        
        has_lm_head = "lm_head" in adapter_cfg.get("target_modules", [])
        if has_lm_head:
            log("重要检测：LoRA target_modules 包含了 'lm_head'，合并后必须强制保持 tie_word_embeddings = False！", "WARN")

        # 3. 准备基座模型路径
        base_model_path = download_or_load_base_model(args.base_model, args.source)

        # 4. 加载 Tokenizer 与基座模型
        log(f"正在加载基座分词器: {base_model_path}...")
        tokenizer = AutoTokenizer.from_pretrained(
            base_model_path,
            trust_remote_code=True,
            use_fast=True
        )

        log(f"正在加载基座模型权重 (dtype=bfloat16/float16)...")
        dtype = torch.bfloat16 if (torch.cuda.is_available() and torch.cuda.is_bf16_supported()) else torch.float16
        if device == "cpu":
            dtype = torch.float32  # CPU 环境下建议使用 float32 保证兼容性与数值精度

        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_path,
            torch_dtype=dtype,
            device_map=device if device != "cpu" else None,
            trust_remote_code=True,
            low_cpu_mem_usage=True
        )
        if device == "cpu":
            base_model.to("cpu")

        # 记录基座模型原始 tie 状态
        orig_tie = getattr(base_model.config, "tie_word_embeddings", False)
        log(f"基座模型初始 config.tie_word_embeddings = {orig_tie}")

        # 5. [前置验证] 运行基座模型前向推理
        base_eval_res = None
        if not args.skip_verify:
            log("正在执行基座模型前向推理（用于基准对比）...")
            base_eval_res = evaluate_test_prompt(base_model, tokenizer, args.test_prompt, device)
            log(f"[基座模型] SECRET logit: {base_eval_res['secret_logit']:.4f} | SAFE logit: {base_eval_res['safe_logit']:.4f} | Diff: {base_eval_res['diff']:.4f} | P(SECRET): {base_eval_res['prob_secret']:.4f}")

        # 6. 加载 LoRA 适配器并执行合并
        log(f"正在挂载 LoRA 权重: {adapter_dir}...")
        peft_model = PeftModel.from_pretrained(
            base_model,
            str(adapter_dir),
            torch_dtype=dtype,
            device_map=device if device != "cpu" else None
        )

        log("执行 model.merge_and_unload() 进行永久权重融合...")
        merged_model = peft_model.merge_and_unload()
        log("权重合并完成！", "SUCCESS")

        # 7. 核心关键处理：显式解绑并物理隔离 lm_head
        log("执行关键安全步骤：强制解绑 lm_head 与 embed_tokens (tie_word_embeddings = False)...")
        
        # (1) 修改模型配置
        merged_model.config.tie_word_embeddings = False
        if hasattr(merged_model, "model") and hasattr(merged_model.model, "config"):
            merged_model.model.config.tie_word_embeddings = False

        # (2) 物理隔离权重张量内存指针，防止 safetensors 导出时误判为共享张量
        if hasattr(merged_model, "lm_head") and hasattr(merged_model.lm_head, "weight"):
            embed_weight = merged_model.model.embed_tokens.weight
            head_weight = merged_model.lm_head.weight
            
            ptr_shared = (embed_weight.data_ptr() == head_weight.data_ptr())
            log(f"权重物理地址检测: embed_ptr={embed_weight.data_ptr()}, head_ptr={head_weight.data_ptr()} (共享内存: {ptr_shared})")
            
            # 无论当前是否共享，显式执行 clone() 并重新封装为独立 Parameter
            merged_model.lm_head.weight = torch.nn.Parameter(head_weight.detach().clone())
            log("已完成 lm_head.weight 的深度拷贝与指针独立化！", "SUCCESS")

        # 8. [后置验证] 对比合并模型与基座模型 Logits
        if not args.skip_verify and base_eval_res is not None:
            log("正在执行合并模型前向推理并执行权重生效判定...")
            merged_eval_res = evaluate_test_prompt(merged_model, tokenizer, args.test_prompt, device)
            log(f"[合并模型] SECRET logit: {merged_eval_res['secret_logit']:.4f} | SAFE logit: {merged_eval_res['safe_logit']:.4f} | Diff: {merged_eval_res['diff']:.4f} | P(SECRET): {merged_eval_res['prob_secret']:.4f}")

            # 计算全词表最大绝对偏差
            diff_tensor = (merged_eval_res["all_logits"] - base_eval_res["all_logits"]).abs()
            max_abs_diff = float(diff_tensor.max().item())
            mean_diff = float(diff_tensor.mean().item())
            target_diff_delta = merged_eval_res["diff"] - base_eval_res["diff"]

            print("\n" + "=" * 60)
            print("                 LoRA 融合效果对比报告")
            print("=" * 60)
            print(f"测试 Prompt: {args.test_prompt.strip()[:50]}...")
            print(f"全词表 Logits 最大变动 (Max Abs Diff) : {max_abs_diff:.6f}")
            print(f"全词表 Logits 平均变动 (Mean Abs Diff): {mean_diff:.6f}")
            print("-" * 60)
            print(f"基座模型: SECRET={base_eval_res['secret_logit']:.4f}, SAFE={base_eval_res['safe_logit']:.4f}, 差值(S-S)={base_eval_res['diff']:.4f}, P(SECRET)={base_eval_res['prob_secret']:.2%}")
            print(f"合并模型: SECRET={merged_eval_res['secret_logit']:.4f}, SAFE={merged_eval_res['safe_logit']:.4f}, 差值(S-S)={merged_eval_res['diff']:.4f}, P(SECRET)={merged_eval_res['prob_secret']:.2%}")
            print(f"决策偏置变化量 (Merged Diff - Base Diff): {target_diff_delta:+.4f}")
            print("=" * 60 + "\n")

            # 严格断言：若改动量极小 (< 1e-4)，说明 LoRA 根本没有融入模型！
            if max_abs_diff < 1e-4:
                raise RuntimeError("严重警告：合并前后模型的输出 Logits 几乎完全相同！LoRA 权重可能未正确融合，请检查 adapter 结构！")
            else:
                log("Logits 显著变动校验通过，确认 LoRA 权重已成功融合入模型参数！", "SUCCESS")

        # 9. 保存合并后的完整 Hugging Face 模型与分词器
        out_path = Path(args.output_dir).expanduser().resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        log(f"正在保存完整模型至: {out_path} (格式: SafeTensors)...")

        merged_model.save_pretrained(
            str(out_path),
            safe_serialization=True,
            max_shard_size="5GB"
        )
        tokenizer.save_pretrained(str(out_path))

        # 10. 二次强校验并修正 config.json 中的 tie_word_embeddings
        saved_config_path = out_path / "config.json"
        if saved_config_path.exists():
            with open(saved_config_path, "r", encoding="utf-8") as f:
                saved_cfg = json.load(f)
            
            if saved_cfg.get("tie_word_embeddings") is not False:
                log("检测到保存的 config.json 中 tie_word_embeddings 未置为 false，执行强制覆写修正...", "WARN")
                saved_cfg["tie_word_embeddings"] = False
                with open(saved_config_path, "w", encoding="utf-8") as f:
                    json.dump(saved_cfg, f, indent=2, ensure_ascii=False)
            log("已确认 config.json 中的 \"tie_word_embeddings\": false！", "SUCCESS")

        # 统计保存的文件大小
        total_size_bytes = sum(f.stat().st_size for f in out_path.glob("*") if f.is_file())
        total_size_mb = total_size_bytes / (1024 * 1024)
        log(f"合并模型已成功输出到 {out_path}，总大小: {total_size_mb:.2f} MB", "SUCCESS")
        log("提示：因解绑了 lm_head 与 embed_tokens，参数量增加约 136M（总计约 630M），符合预期！")

    finally:
        # 清理临时解压目录
        if temp_dir_obj is not None:
            try:
                temp_dir_obj.cleanup()
                log("已自动清理临时解压目录。")
            except Exception:
                pass


if __name__ == "__main__":
    main()
