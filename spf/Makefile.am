pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = spf.pc
EXTRA_DIST = $(pkgconfig_DATA)

AM_CFLAGS = -Wall -Werror
AM_CFLAGS += -I ./api
AM_CFLAGS += -I ./api/apm
AM_CFLAGS += -I ./api/ar_utils
AM_CFLAGS += -I ./api/modules
AM_CFLAGS += -I ./api/vcpm

spf_sources = ./api/apm/apm_api.h \
                ./api/apm/apm_api_version.h \
                ./api/apm/apm_container_api.h \
                ./api/apm/apm_graph_properties.h \
                ./api/apm/apm_memmap_api.h \
                ./api/apm/apm_module_api.h \
                ./api/apm/apm_sub_graph_api.h \
                ./api/ar_utils/spf_begin_pack.h \
                ./api/ar_utils/spf_begin_pragma.h \
                ./api/ar_utils/spf_end_pack.h \
                ./api/ar_utils/spf_end_pragma.h \
                ./api/ar_utils/ar_error_codes.h \
                ./api/ar_utils/ar_guids.h \
                ./api/ar_utils/ar_ids.h \
                ./api/ar_utils/ar_defs.h \
                ./api/asps/asps_ads_usecase_api.h \
                ./api/asps/asps_upd_usecase_api.h \
                ./api/asps/asps_acd_usecase_api.h \
                ./api/asps/asps_acm_api.h \
                ./api/modules/aac_decoder_api.h \
                ./api/modules/aac_encoder_api.h \
                ./api/modules/acd_api.h \
                ./api/modules/alac_decoder_api.h \
                ./api/modules/amdb_api.h \
                ./api/modules/amrwb_decoder_api.h \
                ./api/modules/amrwb_encoder_api.h \
                ./api/modules/amrwbplus_decoder_api.h \
                ./api/modules/ape_decoder_api.h \
                ./api/modules/aptx-adaptive3-ble-encoder-api.h \
                ./api/modules/aptx_adaptive_encoder_api.h \
                ./api/modules/aptx_adaptive_swb_decoder_api.h \
                ./api/modules/aptx_adaptive_swb_encoder_api.h \
                ./api/modules/aptx_classic_decoder_api.h \
                ./api/modules/aptx_classic_encoder_api.h \
                ./api/modules/aptx_hd_decoder_api.h \
                ./api/modules/aptx_hd_encoder_api.h \
                ./api/modules/audio_dam_buffer_api.h \
                ./api/modules/audio_hw_clk_api.h \
                ./api/modules/audio_hw_dma_api.h \
                ./api/modules/audio_hw_lpm_api.h \
                ./api/modules/audio_if_api.h \
                ./api/modules/celt_enc_api.h \
                ./api/modules/codec_dma_api.h \
                ./api/modules/codec_metadata_api.h \
                ./api/modules/common_enc_dec_api.h \
                ./api/modules/contexts_api.h \
                ./api/modules/cop_packetizer_cmn_api.h \
                ./api/modules/cop_packetizer_v0_api.h \
                ./api/modules/cop_v2_depacketizer_api.h \
                ./api/modules/cop_v2_packetizer_api.h \
                ./api/modules/cps_data_router.h \
                ./api/modules/data_logging_api.h \
                ./api/modules/data_marker_api.h \
                ./api/modules/detection_cmn_api.h \
                ./api/modules/display_port_api.h \
                ./api/modules/dls_api.h \
                ./api/modules/dls_log_pkt_hdr_api.h \
                ./api/modules/dtmf_detection_api.h \
                ./api/modules/flac_decoder_api.h \
                ./api/modules/fluence_ffv_common_calibration.h \
                ./api/modules/gapless_api.h \
                ./api/modules/gate_api.h \
                ./api/modules/hw_core_api.h \
                ./api/modules/hw_intf_cmn_api.h \
                ./api/modules/i2s_api.h \
                ./api/modules/imcl_fwk_intent_api.h \
                ./api/modules/imcl_spm_intent_api.h \
                ./api/modules/irm_api.h \
                ./api/modules/lc3_decoder_api.h \
                ./api/modules/lc3_encoder_api.h \
                ./api/modules/ldac_encoder_api.h \
                ./api/modules/lpass_core_api.h \
                ./api/modules/mailbox_api.h \
                ./api/modules/media_fmt_api_basic.h \
                ./api/modules/media_fmt_api_ext.h \
                ./api/modules/media_fmt_api.h \
                ./api/modules/metadata_api.h \
                ./api/modules/module_cmn_api.h \
                ./api/modules/mp2_decoder_api.h \
                ./api/modules/mp3_decoder_api.h \
                ./api/modules/mspp_module_calibration_api.h \
                ./api/modules/mux_demux_api.h \
                ./api/modules/opus_decoder_api.h \
                ./api/modules/pcm_decoder_api.h \
                ./api/modules/pcm_encoder_api.h \
                ./api/modules/pcm_tdm_api.h \
                ./api/modules/pop_suppressor_api.h \
                ./api/modules/priority_sync_api.h \
                ./api/modules/prm_api.h \
                ./api/modules/rate_adapted_timer_api.h \
                ./api/modules/rd_sh_mem_client_api.h \
                ./api/modules/rd_sh_mem_ep_api.h \
                ./api/modules/rtm_logging_api.h \
                ./api/modules/rt_proxy_api.h \
                ./api/modules/rx_haptics_api.h \
                ./api/modules/sa_hdt_api.h \
                ./api/modules/sbc_decoder_api.h \
                ./api/modules/sbc_encoder_api.h \
                ./api/modules/sh_mem_pull_push_mode_api.h \
                ./api/modules/slimbus_api.h \
                ./api/modules/smart_sync_api.h \
                ./api/modules/sp_dc_api.h \
                ./api/modules/splitter_api.h \
                ./api/modules/spr_api.h \
                ./api/modules/sp_rx.h \
                ./api/modules/sp_vi.h \
                ./api/modules/sync_api.h \
                ./api/modules/test_module_api.h \
                ./api/modules/trm_api.h \
                ./api/modules/tsm_module_api.h \
                ./api/modules/tty_cmn_api.h \
                ./api/modules/usb_api.h \
                ./api/modules/us_detect_api.h \
                ./api/modules/us_gen_api.h \
                ./api/modules/vocoder_cmn_api.h \
                ./api/modules/vorbis_decoder_api.h \
                ./api/modules/wr_sh_mem_client_api.h \
                ./api/modules/wr_sh_mem_ep_api.h \
                ./api/modules/wsa_haptics_vi_api.h \
                ./api/modules/congestion_buf_api.h \
                ./api/modules/jitter_buf_api.h \
                ./api/vcpm/vcpm_api.h \
                ./api/modules/asr_module_calibration_api.h \
                ./api/modules/tts_module_calibration_api.h \
                ./api/modules/nmt_module_calibration_api.h \
                ./api/modules/us_tone_renderer_api.h \
                ./api/modules/mma_api.h \
                ./api/modules/sound_dose_api.h \
                ./api/modules/sdz_api.h

asps_sources =  ./api/asps/asps_ads_usecase_api.h \
                ./api/asps/asps_upd_usecase_api.h \
                ./api/asps/asps_acd_usecase_api.h \
                ./api/asps/asps_acm_api.h \
                ./api/asps/asps_sdz_usecase_api.h \
                ./api/asps/asps_us_rendering_usecase_api.h

spf_includedir = $(includedir)/spf
spf_include_HEADERS = $(spf_sources)

asps_includedir = $(includedir)/spf/asps
asps_include_HEADERS = $(asps_sources)

#LIBRARY for LE apps
lib_LTLIBRARIES = libar-spfhdrs.la
libar_spfhdrs_la_CC = @CC@
libar_spfhdrs_la_SOURCES = $(spf_sources) $(asps_sources)
libar_spfhdrs_la_CFLAGS = $(AM_CFLAGS)
libar_spfhdrs_la_LDFLAGS = -shared -version-number @LT_VERSION_NUMBER@
